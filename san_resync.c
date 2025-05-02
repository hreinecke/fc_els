/*
 * Copyright(c) 2013 Hannes Reinecke, SUSE Linux Products GmbH
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

/*
 * san_resync - resynchronize SAN port states
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
#include "fc_gs.h"
#include "fc_els.h"
#include "scsi_bsg_fc.h"

#include "fc_nameserver.h"

extern void tdestroy(void *, void (*)(void *));

static const char *cmdname = "san_resync";

#define DEF_ELS_TIMEOUT 20      /* Default ELS timeout: 20 seconds */
#define MAX_SENSE_LEN	96	/* SCSI_SENSE_BUFFERSIZE */
/* FC ELS ECHO Command takes 4 bytes */
#define FP_LEN_ECHO	sizeof(u_int32_t)
#define FP_LEN_DEF	32	/* default ping payload length */
#define FP_LEN_PAD	32	/* extra length for response */

static int els_timeout = DEF_ELS_TIMEOUT;
static int fp_hba = -1;	/* number of fc_host to be used */
static fc_fid_t fp_hba_did;
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
 * ELS_ECHO request format being used.
 * Put a sequence number in the payload, followed by the pattern.
 */
struct fcping_echo {
	uint8_t		fe_op;		/* opcode */
	uint8_t		fe_resvd[3];	/* reserved, must be zero */
	uint32_t	fe_seq;		/* sequence number */
};

/*
 * Setup buffer to be sent.
 */
struct fcping_echo *
fp_buf_setup(int buf_len)
{
	struct fcping_echo *ep;
	uint8_t *pp;
	int len;
	int i;

	/*
	 * Alloc extra in case of odd len or shorter than minimum.
	 */
	len = buf_len + sizeof(*ep) + sizeof(uint32_t);
	ep = calloc(1, len);
	if (ep == NULL)
		return NULL;
	ep->fe_op = ELS_ECHO;
	ep->fe_seq = htonl(1);
	i = 0;
	for (pp = (uint8_t *) (ep + 1); pp < (uint8_t *) ep + buf_len; pp++)
		*pp = i++;
	return ep;
}

static int
send_els_echo(int hba_num, int rport, void *fp_buf, uint32_t fp_len,
	      unsigned char *resp, uint32_t *resp_len)
{
	struct fc_bsg_request cdb;
	char bsg_dev[256];
	char sense[MAX_SENSE_LEN];
	struct sg_io_v4 sg_io;
	int fp_rport_fd, rc;

	sprintf(bsg_dev, "/dev/bsg/rport-%d:0-%d", hba_num, rport);
	fp_rport_fd = open(bsg_dev, O_RDWR);
	if (fp_rport_fd < 0) {
		fprintf(stderr, "rport-%d:0-%d: cannot open bsg %s: %m\n",
			hba_num, rport, bsg_dev);
		system_errors++;
		return ENOENT;
	}
	cdb.msgcode = FC_BSG_RPT_ELS;
	cdb.rqst_data.h_els.command_code = ELS_ECHO;

	sg_io.guard = 'Q';
	sg_io.protocol = BSG_PROTOCOL_SCSI;
	sg_io.subprotocol = BSG_SUB_PROTOCOL_SCSI_TRANSPORT;
	sg_io.request_len = sizeof(cdb);
	sg_io.request = (unsigned long)&cdb;
	sg_io.dout_xfer_len = fp_len;
	sg_io.dout_xferp = (unsigned long)fp_buf;
	sg_io.din_xfer_len = *resp_len;
	sg_io.din_xferp = (unsigned long)resp;
	sg_io.max_response_len = sizeof(sense);
	sg_io.response = (unsigned long)sense;
	sg_io.timeout = (unsigned long)els_timeout * 1000;
	memset(sense, 0, sizeof(sense));

	rc = ioctl(fp_rport_fd, SG_IO, &sg_io);
	if (rc >= 0) {
		*resp_len = sg_io.din_xfer_len - sg_io.din_resid;
		rc = 0;
	} else {
		fprintf(stderr, "rport-%d:0-%d: bsg ioctl failed: %m\n",
			hba_num, rport);
		system_errors++;
		rc = -errno;
	}
	close(fp_rport_fd);
	return rc;
}

/*
 * Send ELS ECHO.
 */
static int fp_send_ping(int hba_num, int rport, fc_fid_t did)
{
	struct fcping_echo *fp_buf, *ep;
	u_int32_t fp_len = FP_LEN_DEF + FP_LEN_ECHO;
	int rc;
	uint32_t resp_len;
	unsigned char resp[FP_LEN_DEF + FP_LEN_ECHO + FP_LEN_PAD];

	resp_len = sizeof(resp);
	memset(resp, 0x0, sizeof(resp));
	fp_buf = fp_buf_setup(fp_len);
	if (!fp_buf) {
		fprintf(stderr, "rport-%d:0-%d: cannot allocate ELS buffer\n",
			hba_num, rport);
		system_errors++;
		return -ENOMEM;
	}

	/* send ELS ECHO frame and receive */
	rc = send_els_echo(hba_num, rport, fp_buf, fp_len, resp, &resp_len);
	if (!rc) {
		ep = (struct fcping_echo *) resp;
		if (ep->fe_op == ELS_LS_ACC) {
			if (memcmp((char *) ep + 1,
				   (char *) fp_buf + 1, fp_len - 1) == 0)
				rc = 0;
			else {
				rc = ENODATA;
				els_errors++;
			}
		} else if (ep->fe_op == ELS_LS_RJT) {
			rc = EAGAIN;
			els_errors++;
		} else {
			rc = ECOMM;
			els_errors++;
		}
	}
	free(fp_buf);
	return rc;
}

int rport_compare (const void *pa, const void *pb)
{
	const struct rport_type_t *rpa = pa;
	const struct rport_type_t *rpb = pb;

	if (rpa->did < rpb->did)
		return -1;
	if (rpa->did > rpb->did)
		return 1;
	return 0;
}

void rport_check(struct rport_type_t *rp)
{
	char port_name[64], port_state[64];
	ssize_t len;
	int rc, retry = 5;
	fc_fid_t did;

	if (rp->rport == -1)
		sprintf(port_name,"rport-%d:0-X", rp->hba);
	else
		sprintf(port_name,"rport-%d:0-%d", rp->hba, rp->rport);

	if (verbose)
		printf("%s: DID %06x WWPN 0x%08" PRIx64 " WWNN 0x%08" PRIx64 "\n",
		       port_name, rp->did, rp->wwpn, rp->wwnn);
	if (FCID_IS_WKA(rp->did))
		return;

	if (rp->rport == -1) {
		if (verbose)
			printf("\tState: removed, registered\n");
		port_errors++;
		return;
	}
	memset(port_state, 0x0, sizeof(port_state));
	rc = fc_rport_get_attr(port_name, "port_state",
			       port_state, sizeof(port_state));
	if (rc < 0) {
		if (verbose)
			printf("\tState: unknown\n");
		port_errors++;
		return;
	}
	len = strlen(port_state);
	if (port_state[len - 1] == '\n')
		port_state[len - 1] = '\0';
	if (verbose)
		printf("\tState: %s", port_state);
	if (strcmp(port_state, "Online")) {
		/*
		 * Port is not online, so internal state machine
		 * has detected an issue. No error.
		 */
		if (verbose)
			printf("\n");
		return;
	}

	did = fp_lookup_target_by_wwpn(fp_hba, rp->wwpn);
	if (did && did == rp->did) {
		if (verbose)
			printf(", registered");
	} else {
		if (verbose)
			printf(", unregistered\n");
		if (did)
			port_errors++;
		return;
	}
	if (rp->did == fp_hba_did) {
		printf(", host port\n");
		return;
	}
retry:
	rc = fp_send_ping(fp_hba, rp->rport, rp->did);
	if (rc < 0) {
		if (verbose)
			printf(", failed to send ELS ECHO, error %d\n", -rc);
		port_errors++;
	} else {
		switch (rc) {
		case 0:
			if (verbose)
				printf(", alive\n");
			break;
		case ENODATA:
			if (--retry)
				goto retry;
			if (verbose)
				printf(", ELS ECHO buffer mismatch\n");
			break;
		case EAGAIN:
			if (verbose)
				printf(", ELS ECHO rejected\n");
			port_errors++;
			break;
		default:
			if (verbose)
				printf(", ELS ECHO error %d\n", rc);
			port_errors++;
			break;
		}
	}
}

void rport_print(const void *nodep, const VISIT which, const int depth)
{
	struct rport_type_t *rp;

	switch (which) {
	case preorder:
		break;
	case postorder:
		rp = *(struct rport_type_t **)nodep;
		rport_check(rp);
		break;
	case endorder:
		break;
	case leaf:
		rp = *(struct rport_type_t **)nodep;
		rport_check(rp);
		break;
	}
}

static int
walk_ports(int hba_num, fc_fid_t hba_did)
{
	DIR *dirp;
	struct dirent *dentry;
	int tmp_hba, tmp_bus, tmp_rport, rport_num = -1;
	char attrvalue[512], *endptr;
	struct rport_type_t *rport;
	void *ptr;
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

		rport = malloc(sizeof(struct rport_type_t));
		if (!rport) {
			fprintf(stderr,"%s: out of memory allocating rport\n",
				dentry->d_name);
			system_errors++;
			continue;
		}
		rport->hba = hba_num;
		rport->rport = tmp_rport;
		memset(attrvalue, 0x0, sizeof(attrvalue));
		count = fc_rport_get_attr(dentry->d_name, "port_id",
					  attrvalue, sizeof(attrvalue));
		if (count < 0) {
			system_errors++;
			free(rport);
			continue;
		}

		rport->did = strtoul(attrvalue, &endptr, 16);
		if (attrvalue == endptr) {
			fprintf(stderr, "%s: invalid Port ID %s\n",
				dentry->d_name, attrvalue);
			system_errors++;
			free(rport);
			continue;
		}
		if (FCID_IS_WKA(rport->did)) {
			free(rport);
			continue;
		}
		if (rport->did == hba_did) {
			free(rport);
			continue;
		}
		memset(attrvalue, 0x0, sizeof(attrvalue));
		count = fc_rport_get_attr(dentry->d_name, "port_name",
					  attrvalue, sizeof(attrvalue));
		if (count < 0) {
			system_errors++;
			free(rport);
			continue;
		}
		rport->wwpn = strtoull(attrvalue, &endptr, 16);
		if (attrvalue == endptr) {
			fprintf(stderr, "%s: invalid WWPN %s\n",
				dentry->d_name, attrvalue);
			system_errors++;
			free(rport);
			continue;
		}
		memset(attrvalue, 0x0, sizeof(attrvalue));
		count = fc_rport_get_attr(dentry->d_name, "node_name",
					  attrvalue, sizeof(attrvalue));
		if (count < 0) {
			system_errors++;
			free(rport);
			continue;
		}
		rport->wwnn = strtoull(attrvalue, &endptr, 16);
		if (attrvalue == endptr) {
			fprintf(stderr, "%s: invalid WWNN %s\n",
				dentry->d_name, attrvalue);
			system_errors++;
			free(rport);
			continue;
		}
		ptr = tsearch((void *)rport, &root, rport_compare);
		if (ptr == NULL) {
			fprintf(stderr, "%s: failed to insert rport\n",
				dentry->d_name);
			system_errors++;
			free(rport);
		} else if ((struct rport_type_t *)ptr == rport) {
			fprintf(stderr, "%s: duplicate rport\n",
				dentry->d_name);
			system_errors++;
			free(rport);
		}
	}
	closedir(dirp);
	return rport_num;
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
	while (rc == 0 && rport->did && rport->did != hba_did) {
		did = rport->did;
		ptr = tsearch((void *)rport, &root, rport_compare);
		if (ptr == NULL) {
			fprintf(stderr, "host%d: Failed to insert did %06x\n",
				hba_num, did);
			system_errors++;
		} else if ((struct rport_type_t *)ptr == rport) {
			rport = malloc(sizeof(struct rport_type_t));
			memset(rport, 0x0, sizeof(struct rport_type_t));
		}
		rc = fp_lookup_next_port(fp_hba, wka_fd, did, rport);
	}
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

	fp_options(argc, argv);

	fp_hba_did = fp_find_hba(fp_hba);
	if (!fp_hba_did) {
		return 1;
	}
	if (verbose)
		printf("host%d: DID %06x\n", fp_hba, fp_hba_did);

	walk_ports(fp_hba, fp_hba_did);

	walk_ns(fp_hba, fp_hba_did);

	twalk(root, rport_print);
	tdestroy(root, free);

	printf("host %d: %d System errors, %d ELS errors, %d port mismatches\n",
	       fp_hba, system_errors, els_errors, port_errors);
	if (port_errors)
		rc |= 1;
	if (els_errors)
		rc |= 2;
	if (system_errors)
		rc |= 4;
	return rc;
}
