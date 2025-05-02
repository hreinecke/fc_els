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
 * san_zoning - query zone name server
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

#include "fc_ms.h"
#include "fc_gs.h"
#include "fc_els.h"
#include "scsi_bsg_fc.h"

#include "fc_nameserver.h"

static const char *cmdname = "san_zoning";

#define DEF_ELS_TIMEOUT 20      /* Default ELS timeout: 20 seconds */
#define MAX_SENSE_LEN	96	/* SCSI_SENSE_BUFFERSIZE */
/* FC ELS ECHO Command takes 4 bytes */
#define FP_LEN_ECHO	sizeof(u_int32_t)
#define FP_LEN_DEF	32	/* default ping payload length */
#define FP_LEN_PAD	32	/* extra length for response */

static int els_timeout = DEF_ELS_TIMEOUT;
static int fp_hba = -1;	/* number of fc_host to be used */
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
 * Get enhanced zoning support
 */
static int
fp_gs_gfez(int hba_num)
{
	char bsg_dev[80];
	int wka_port = -1;
	struct ct_gfez_ze {
		uint8_t  sw_name[8];
		uint32_t flags;
	};
	struct fc_ct_hdr req;
	struct ct_gfez_req {
		struct fc_ct_hdr hdr;
		uint32_t flags;
		uint8_t  resv[3];
		uint8_t  num_sw;
		struct ct_gfez_ze entry[0];
	} resp;
	struct fc_bsg_request cdb;
	struct fc_bsg_reply reply;
	struct sg_io_v4 sg_io;
	uint8_t *response = (uint8_t *)&resp;
	int fp_rport_fd;
	int cmd, rc = 0;

	wka_port = fp_find_did(hba_num, FC_WKA_MANAGEMENT_SERVICE);
	if (wka_port < 0) {
		fprintf(stderr, "host%d: No remote port found for WKA %06lx\n",
		       hba_num, (unsigned long)FC_WKA_MANAGEMENT_SERVICE);
		return ENXIO;
	}

	sprintf(bsg_dev, "/dev/bsg/rport-%d:0-%d", hba_num, wka_port);
	fp_rport_fd = open(bsg_dev, O_RDWR);
	if (fp_rport_fd < 0) {
		fprintf(stderr, "host%d: Cannot open bsg device %s: %s\n",
			hba_num, bsg_dev, strerror(errno));
		return errno;
	}
	memset((char *)&cdb, 0, sizeof(cdb));
	memset(&req, 0, sizeof(req));

	req.ct_rev = FC_CT_REV;
	req.ct_fs_type = FC_FST_MGMT;
	req.ct_fs_subtype = FC_MS_SUBTYPE_ZONE;
	req.ct_options = (1 << 6);
	req.ct_cmd = htons(FC_MS_ZS_GFEZ);
	req.ct_mr_size = htons(sizeof(resp));

	cdb.msgcode = FC_BSG_RPT_CT;
	memcpy(&cdb.rqst_data.r_ct.preamble_word0, &req,
	       3 * sizeof(uint32_t));

	sg_io.guard = 'Q';
	sg_io.protocol = BSG_PROTOCOL_SCSI;
	sg_io.subprotocol = BSG_SUB_PROTOCOL_SCSI_TRANSPORT;
	sg_io.request_len = sizeof(cdb);
	sg_io.request = (uintptr_t)&cdb;
	sg_io.dout_xfer_len = sizeof(req);
	sg_io.dout_xferp = (uintptr_t)&req;
	sg_io.din_xfer_len = sizeof(resp);
	sg_io.din_xferp = (uintptr_t)&resp;
	sg_io.max_response_len = sizeof(reply);
	sg_io.response = (uintptr_t)&reply;
	sg_io.timeout = 1000;	/* millisecond */
	memset(&reply, 0, sizeof(reply));
	memset(&resp, 0, sizeof(resp));

	rc = ioctl(fp_rport_fd, SG_IO, &sg_io);
	if (rc < 0) {
		fprintf(stderr, "host%d: GFEZ error; %s\n", hba_num,
			strerror(errno));
		close(fp_rport_fd);
		return errno;
	}

	cmd = ((response[8]<<8) | response[9]) & 0xffff;
	if (cmd == FC_FS_RJT) {
		if (response[13] == FC_FS_RJT_UNABL &&
		    (response[14] == FC_FS_EXP_PNAM ||
		     response[14] == FC_FS_EXP_NNAM)) {
			fprintf(stderr, "host%d: GFEZ rejected, "
				"not registered\n", hba_num);
		} else
			fprintf(stderr, "host%d: GFEZ rejected, "
				"reason %02x/%02x\n", hba_num,
				response[13], response[14]);
		close(fp_rport_fd);
		return 0;
	} else if (cmd != FC_FS_ACC) {
		fprintf(stderr, "host%d: GFEZ result %x\n", hba_num, cmd);
		close(fp_rport_fd);
		return 0;
	}

	printf("# Switches: %d\n", resp.num_sw);
	printf("Flags: %08x\n", ntohl(resp.flags));
	close(fp_rport_fd);
	return 0;
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

	rc = fp_gs_gfez(fp_hba);
	return rc;
}
