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

#include "fc_nameserver.h"

static const char *cmdname = "san_nswalk";

#define DEF_ELS_TIMEOUT 20      /* Default ELS timeout: 20 seconds */
#define MAX_SENSE_LEN	96	/* SCSI_SENSE_BUFFERSIZE */
/* FC ELS ECHO Command takes 4 bytes */
#define FP_LEN_ECHO	sizeof(u_int32_t)
#define FP_LEN_DEF	32	/* default ping payload length */
#define FP_LEN_PAD	32	/* extra length for response */

static int els_timeout = DEF_ELS_TIMEOUT;
static int fp_hba = -1;	/* number of fc_host to be used */
static void *root = NULL;
static int system_errors;
static int els_errors;
static int port_errors;
static int verbose;

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
 * Query unzoned name server.
 */
static int
fp_ns_get_device_list(int hba_num, uint32_t op, fc_wwn_t wwn,
	     char *response, size_t *resp_len)
{
	char bsg_dev[80];
	int wka_port = -1;
	struct ct_get_id {
		struct fc_ct_hdr hdr;
		uint8_t	 wwn[8];
	} ct;
	struct fc_bsg_request cdb;
	struct fc_bsg_reply reply;
	struct sg_io_v4 sg_io;
	size_t actual_len;
	int fp_rport_fd;
	int cmd, rc = 0;

	wka_port = fp_find_did(hba_num, FC_WKA_UNZONED_NAME_SERVER);
	if (wka_port < 0) {
		fprintf(stderr, "host%d: No remote port found for WKA %06lx\n",
		       hba_num, (unsigned long)FC_WKA_UNZONED_NAME_SERVER);
		system_errors++;
		return ENXIO;
	}

	sprintf(bsg_dev, "/dev/bsg/rport-%d:0-%d", hba_num, wka_port);
	fp_rport_fd = open(bsg_dev, O_RDWR);
	if (fp_rport_fd < 0) {
		fprintf(stderr, "host%d: Cannot open bsg device %s: %s\n",
			hba_num, bsg_dev, strerror(errno));
		system_errors++;
		return errno;
	}
	memset((char *)&cdb, 0, sizeof(cdb));
	memset(&ct, 0, sizeof(ct));
	ct.hdr.ct_rev = FC_CT_REV;
	ct.hdr.ct_fs_type = FC_FST_DIR;
	ct.hdr.ct_fs_subtype = FC_NS_SUBTYPE;
	ct.hdr.ct_options = 0;
	ct.hdr.ct_cmd = htons(op);
	ct.hdr.ct_mr_size = *resp_len;

	hton64(ct.wwn, wwn);

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

	rc = ioctl(fp_rport_fd, SG_IO, &sg_io);
	if (rc < 0) {
		fprintf(stderr, "host%d: %s error; %s\n", hba_num,
			op == FC_NS_GID_PN ? "GID_PN" : "GID_NN",
			strerror(errno));
		close(fp_rport_fd);
		system_errors++;
		return errno;
	}

	cmd = ((response[8]<<8) | response[9]) & 0xffff;
	if (cmd == FC_FS_RJT) {
		if (response[13] == FC_FS_RJT_UNABL &&
		    (response[14] == FC_FS_EXP_PNAM ||
		     response[14] == FC_FS_EXP_NNAM)) {
			fprintf(stderr, "host%d: %s rejected, "
				"not registered\n", hba_num,
				op == FC_NS_GID_PN ? "GID_PN" : "GID_NN");
			port_errors++;
		} else {
			fprintf(stderr, "host%d: %s rejected, "
				"reason %02x/%02x\n", hba_num,
				op == FC_NS_GID_PN ? "GID_PN" : "GID_NN",
				response[13], response[14]);
			els_errors++;
		}
		close(fp_rport_fd);
		*resp_len = 0;
		return 0;
	} else if (cmd != FC_FS_ACC) {
		fprintf(stderr, "host%d: %s result %x\n", hba_num,
			op == FC_NS_GID_PN ? "GID_PN" : "GID_NN", cmd);
		close(fp_rport_fd);
		*resp_len = 0;
		els_errors++;
		return 0;
	}

	actual_len = reply.reply_payload_rcv_len;
	if (actual_len < *resp_len)
		*resp_len = actual_len;

	close(fp_rport_fd);
	return 0;
}

static int
walk_ns(int hba_num, fc_fid_t hba_did)
{
	int wka_num, rc;
	int wka_fd;
	fc_fid_t did;
	char bsg_dev[80];
	struct rport_type_t *rport;
	void *ptr;

	wka_num = fp_find_did(hba_num, FC_WKA_DIRECTORY_SERVICE);
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
	rc = fp_lookup_next_port(fp_hba, wka_fd, hba_did, rport);
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
