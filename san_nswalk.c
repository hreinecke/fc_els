/*
 * Copyright(c) 2013 Hannes Reinecke, SUSE Linux Products GmbH
 *
 * san_nswalk - get portnames from unzoned server
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <malloc.h>
#include <signal.h>
#include <dirent.h>
#include <syslog.h>
#include <search.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/bsg.h>

typedef uint8_t u8;
#include <scsi/sg.h>

#include "fc_ns.h"
#include "fc_ms.h"
#include "fc_gs.h"
#include "fc_els.h"
#include "scsi_bsg_fc.h"

typedef uint64_t fc_wwn_t;    /* world-wide name */
typedef uint32_t fc_fid_t;   /* fabric address */

extern void tdestroy(void *, void (*)(void *));

static const char *cmdname = "san_resync";

#define DEF_ELS_TIMEOUT 20      /* Default ELS timeout: 20 seconds */
#define MAX_SENSE_LEN	96	/* SCSI_SENSE_BUFFERSIZE */
/* FC ELS ECHO Command takes 4 bytes */
#define FP_LEN_ECHO	sizeof(u_int32_t)
#define FP_LEN_DEF	32	/* default ping payload length */
#define FP_LEN_PAD	32	/* extra length for response */

/* Check if it is WKA according to FC-FS-3 Rev 1.00 Clause 11 Table 30 */
#define FCID_IS_WKA(i) ((((i) >= 0xfffc01) && ((i) <= 0xfffcfe)) || \
			(((i) >= 0xfffff0) && ((i) <= 0xffffff)))

#define FC_WKA_FABRIC_CONTROLLER ((fc_fid_t)0xfffffd)
#define FC_WKA_DIRECTORY_SERVICE ((fc_fid_t)0xfffffc)
#define FC_WKA_MANAGEMENT_SERVER ((fc_fid_t)0xfffffa)

static int els_timeout = DEF_ELS_TIMEOUT;
static int fp_hba = -1;	/* number of fc_host to be used */
static void *root = NULL;
static int system_errors;
static int els_errors;
static int port_errors;
static int verbose;

#define hton24(p, v)				\
	do {					\
		p[0] = (((v) >> 16) & 0xFF);	\
		p[1] = (((v) >> 8) & 0xFF);	\
		p[2] = ((v) & 0xFF);		\
	} while (0)

#define hton64(p, v)					\
	do {						\
		p[0] = (u_char) ((v) >> 56) & 0xFF;	\
		p[1] = (u_char) ((v) >> 48) & 0xFF;	\
		p[2] = (u_char) ((v) >> 40) & 0xFF;	\
		p[3] = (u_char) ((v) >> 32) & 0xFF;	\
		p[4] = (u_char) ((v) >> 24) & 0xFF;	\
		p[5] = (u_char) ((v) >> 16) & 0xFF;	\
		p[6] = (u_char) ((v) >> 8) & 0xFF;	\
		p[7] = (u_char) (v) & 0xFF;		\
	} while (0)

static void
fp_usage()
{
	fprintf(stderr,
		"Usage: %s [ -? ] [-v] [ -t <timeout> ] -h <hba>\n"
		"  flags:\n"
		"     -?:            This text\n"
		"     -v:            Increase output verbosity\n"
		"     -t:            ELS timeout (in seconds, default %d)\n"
		"     -h <hba>:      HBA number\n",
		cmdname, els_timeout);

	exit(1);
}

/*
 * Handle options.
 */
static void
fp_options(int argc, char *argv[])
{
	int opt;
	char *endptr;
	int parse_err = 0;

	if (argc <= 1)
		fp_usage();

	while ((opt = getopt(argc, argv, "?vh:t:")) != -1) {
		switch (opt) {
		case 'h':
			fp_hba = (int)strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				fprintf(stderr, "Bad hba number %s\n", optarg);
				parse_err++;
			}
			break;
		case 't':
			els_timeout = (int)strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				fprintf(stderr, "Invalid ELS timeout %s\n",
					optarg);
				parse_err++;
			}
			break;
		case 'v':
			verbose++;
			break;
		case '?':
		default:
			fp_usage();	/* exits */
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (fp_hba == -1) {
		fprintf(stderr, "FC host not specified");
		parse_err++;
	}

	if (parse_err)
		fp_usage();

	return;
}

/*
 * Read fc_remote_port attribute
 */
int
fc_rport_get_attr(const char *rport, const char *attr,
		  char *value, int value_len)
{
	char attrpath[256];
	int fd, count;

	sprintf(attrpath, "/sys/class/fc_remote_ports/%s/%s", rport, attr);
	fd = open(attrpath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: Failed to open %s: %m\n",
			rport, attrpath);
		return -errno;
	}
	count = read(fd, value, value_len);
	if (count < 0) {
		fprintf(stderr, "%s: Cannot read from %s: %m\n",
			rport, attrpath);
	} else if (value[count - 1] == '\n') {
		value[count - 1] = '\0';
		count--;
	}
	close(fd);
	return count;
}

/*
 * Lookup specified adapter from sysfs
 */
static fc_fid_t
fp_find_hba(int hba_num)
{
	fc_fid_t did = (fc_fid_t)0;
	char attrpath[256], attrvalue[512], *endptr;
	int fd;
	ssize_t count;

	sprintf(attrpath, "/sys/class/fc_host/host%d/port_id", hba_num);
	fd = open(attrpath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "host%d not found\n", hba_num);
		return did;
	}
	count = read(fd, attrvalue, sizeof(attrvalue));
	if (count < 0) {
		fprintf(stderr, "host%d: Cannot read from %s: %d\n",
			hba_num, attrpath, errno);
		return did;
	}
	close(fd);
	did = strtoull(attrvalue, &endptr, 16);
	if (attrvalue == endptr) {
		fprintf(stderr, "host%d: Invalid Port ID %s\n",
			hba_num, attrvalue);
		did = (fc_fid_t)0;
	}
	return did;
}

static int
fp_find_did(int hba_num, fc_fid_t did)
{
	DIR *dirp;
	struct dirent *dentry;
	int tmp_hba, tmp_bus, tmp_rport, rport_num = -1;
	char attrvalue[512], *endptr;
	fc_fid_t tmp_did = (fc_fid_t)0;
	ssize_t count;

	dirp = opendir("/sys/class/fc_remote_ports");
	while ((dentry = readdir(dirp)) != NULL) {
		if (strncmp(dentry->d_name, "rport-", 6))
			continue;
		if (sscanf(dentry->d_name, "rport-%d:%d-%d",
			   &tmp_hba, &tmp_bus, &tmp_rport) != 3)
			continue;
		if (tmp_hba != hba_num)
			continue;
		if (tmp_bus != 0) {
			fprintf(stderr, "%s: invalid bus number %d\n",
				dentry->d_name, tmp_bus);
			system_errors++;
			continue;
		}

		count = fc_rport_get_attr(dentry->d_name, "port_id",
					  attrvalue, sizeof(attrvalue));
		if (count < 0) {
			system_errors++;
			break;
		}

		tmp_did = strtoull(attrvalue, &endptr, 16);
		if (attrvalue == endptr) {
			fprintf(stderr, "%s: Invalid Port ID %s\n",
				dentry->d_name, attrvalue);
			tmp_did = (fc_fid_t)0;
			system_errors++;
		}
		if (did == tmp_did) {
			rport_num = tmp_rport;
			break;
		}
	}
	closedir(dirp);
	return rport_num;
}

/*
 * Query unzoned name server.
 */
static int
fp_ns_get_nxt(int hba_num, int fd, fc_fid_t did,
	      unsigned char *response, size_t *resp_len)
{
	struct ct_ga_nxt {
		struct fc_ct_hdr hdr;
		uint8_t reserved;
		uint8_t port_id[3];
	} ct;
	struct fc_bsg_request cdb;
	struct fc_bsg_reply reply;
	struct sg_io_v4 sg_io;
	size_t actual_len;
	int cmd, rc = 0;

	memset((char *)&cdb, 0, sizeof(cdb));
	memset(&ct, 0, sizeof(ct));
	ct.hdr.ct_rev = FC_CT_REV;
	ct.hdr.ct_fs_type = FC_FST_MGMT;
	ct.hdr.ct_fs_subtype = FC_MS_SUBTYPE_UNZONE;
	ct.hdr.ct_options = 0;
	ct.hdr.ct_cmd = htons(FC_NS_GA_NXT);
	ct.hdr.ct_mr_size = *resp_len;
	hton24(ct.port_id, did);
	cdb.msgcode = FC_BSG_RPT_CT;
	memcpy(&cdb.rqst_data.r_ct.preamble_word0, &ct.hdr,
	       3 * sizeof(uint32_t));

	sg_io.guard = 'Q';
	sg_io.protocol = BSG_PROTOCOL_SCSI;
	sg_io.subprotocol = BSG_SUB_PROTOCOL_SCSI_TRANSPORT;
	sg_io.request_len = sizeof(cdb);
	sg_io.request = (uintptr_t)&cdb;
	sg_io.dout_xfer_len = sizeof(ct);
	sg_io.dout_xferp = (uintptr_t)&ct;
	sg_io.din_xfer_len = *resp_len;
	sg_io.din_xferp = (uintptr_t)response;
	sg_io.max_response_len = sizeof(reply);
	sg_io.response = (uintptr_t)&reply;
	sg_io.timeout = 1000;	/* millisecond */
	memset(&reply, 0, sizeof(reply));
	memset(response, 0, *resp_len);

	rc = ioctl(fd, SG_IO, &sg_io);
	if (rc < 0) {
		fprintf(stderr, "host%d: GA_NXT error: %s\n",
			hba_num, strerror(errno));
		system_errors++;
		return rc;
	}

	cmd = ((response[8]<<8) | response[9]) & 0xffff;
	if (cmd != FC_FS_ACC) {
		if (cmd == FC_FS_RJT) {
			fprintf(stderr, "host%d: GA_NXT rejected, "
				"reason %02x/%02x\n",
				hba_num, response[13], response[14]);
			els_errors++;
			rc = EAGAIN;
		} else {
			fprintf(stderr, "host%d: GA_NXT result %x\n",
				hba_num, cmd);
			els_errors++;
			rc = ECOMM;
		}
	} else {
		actual_len = reply.reply_payload_rcv_len;
		if (actual_len < *resp_len)
			*resp_len = actual_len;
	}
	return rc;
}

struct rport_type_t {
	int hba;
	int rport;
	fc_fid_t did;
	fc_wwn_t wwpn;
	fc_wwn_t wwnn;
};

static int
fp_lookup_next_port(int hba_num, int fd, fc_fid_t start_did,
		    struct rport_type_t *rport)
{
	unsigned char response[4096];
	size_t resp_len;
	int rc;

	resp_len = sizeof(response);
	memset(response, 0, sizeof(response));
	rc = fp_ns_get_nxt(hba_num, fd, start_did, response, &resp_len);
	if (rc == 0) {
		rport->rport = -1;
		if (resp_len > 28) {
			rport->hba = hba_num;
			rport->did = ((response[17] << 16) & 0xff0000) |
				((response[18] << 8) & 0x00ff00) |
				(response[19] & 0x0000ff);
			rport->wwpn = ((uint64_t)response[20] << 56) |
				((uint64_t)response[21] << 48) |
				((uint64_t)response[22] << 40) |
				((uint64_t)response[23] << 32) |
				((uint64_t)response[24] << 24) |
				((uint64_t)response[25] << 16) |
				((uint64_t)response[26] <<  8) |
				((uint64_t)response[27]);
		} else {
			fprintf(stderr, "host%d: GA_NXT response len %d\n",
				hba_num, (int)resp_len);
			els_errors++;
			rport->did = 0;
			rport->wwpn = 0;
		}
	}
	return rc;
}

static int
walk_ns(int hba_num, fc_fid_t hba_did)
{
	int wka_num, rc;
	int wka_fd, port_did;
	fc_fid_t did;
	char bsg_dev[80];
	struct rport_type_t *rport;
	void *ptr;

	wka_num = fp_find_did(hba_num, FC_WKA_MANAGEMENT_SERVER);
	if (wka_num < 0) {
		fprintf(stderr, "host%d: No remote port found for WKA %06lx\n",
			hba_num, (unsigned long)FC_WKA_DIRECTORY_SERVICE);
		system_errors++;
		return -ENXIO;
	}

	sprintf(bsg_dev, "/dev/bsg/rport-%d:0-%d", hba_num, wka_num);
	wka_fd = open(bsg_dev, O_RDWR);
	if (wka_fd < 0) {
		fprintf(stderr, "host%d: Cannot open bsg device %s: %s\n",
			hba_num, bsg_dev, strerror(errno));
		system_errors++;
		return -ENODEV;
	}

	rport = malloc(sizeof(struct rport_type_t));
	memset(rport, 0x0, sizeof(struct rport_type_t));
	did = hba_did;
	do {
		rc = fp_lookup_next_port(fp_hba, wka_fd, did, rport);
		if (rc) {
			fprintf(stderr, "host%d: failed to lookup port %06lx\n",
				hba_num, did);
			break;
		}
		printf("host %d: found rport %06lx\n", rport->did);
		did = rport->did;
	} while (did != hba_did);
	free(rport);
	close(wka_fd);
	return rc;
}

/*
 * Main.
 */
int main(int argc, char *argv[])
{
	int rc = 0;
	fc_fid_t fp_hba_did;

	fp_options(argc, argv);

	fp_hba_did = fp_find_hba(fp_hba);
	if (!fp_hba_did) {
		return 1;
	}
	if (verbose)
		printf("host%d: DID %06x\n", fp_hba, fp_hba_did);

	walk_ns(fp_hba, fp_hba_did);

	return rc;
}
