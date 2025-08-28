// SPDX-License-Identifier: GPL-2.0-only
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

#include "fc_sysfs.h"

static const char *cmdname = "san_nswalk";

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
 * Query unzoned name server.
 */
static int
fp_ns_get_nxt(int hba_num, int fd, fc_fid_t did,
	      unsigned char *response, size_t resp_len)
{
	struct ct_ga_nxt {
		struct fc_ct_hdr hdr;
		uint8_t reserved;
		uint8_t port_id[3];
	} ct;
	struct fc_ct_hdr *acc, *rej;
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
	ct.hdr.ct_mr_size = htons(resp_len / 8);
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
	sg_io.din_xfer_len = resp_len;
	sg_io.din_xferp = (uintptr_t)response;
	sg_io.max_response_len = sizeof(reply);
	sg_io.response = (uintptr_t)&reply;
	sg_io.timeout = 1000;	/* millisecond */
	memset(&reply, 0, sizeof(reply));
	memset(response, 0, resp_len);

	rc = ioctl(fd, SG_IO, &sg_io);
	if (rc < 0) {
		fprintf(stderr, "host%d: GA_NXT error: %s\n",
			hba_num, strerror(errno));
		return -errno;
	}

	acc = (struct fc_ct_hdr *)response;
	cmd = htons(acc->ct_cmd);
	if (cmd != FC_FS_ACC) {
		if (cmd == FC_FS_RJT) {
			rej = (struct fc_ct_hdr *)response;
			fprintf(stderr, "host%d: GA_NXT rejected, "
				"reason %02x/%02x\n",
				hba_num, rej->ct_reason, rej->ct_explan);
			rc = -EAGAIN;
		} else {
			fprintf(stderr, "host%d: GA_NXT result %x\n",
				hba_num, cmd);
			rc = -ECOMM;
		}
	} else {
		unsigned int residual = htons(acc->ct_mr_size) * 8;

		if (residual > 0)
			fprintf(stderr, "host%d: GA_NXT missing %u bytes\n",
				hba_num, residual);
		actual_len = reply.reply_payload_rcv_len;
		if (actual_len < resp_len)
			rc = actual_len * 8;
		else
			rc = resp_len;
	}
	return rc;
}

struct rport_type_t {
	int hba;
	int rport;
	fc_fid_t did;
	fc_wwn_t wwpn;
	fc_wwn_t wwnn;
	char spn[256];
	char snn[256];
};

static int
fp_lookup_next_port(int hba_num, int fd, fc_fid_t start_did,
		    struct rport_type_t *rport)
{
	unsigned char response[4096], *pn, *nn;
	char spn[256];
	size_t resp_len;
	int rc;

	resp_len = sizeof(response);
	memset(response, 0, sizeof(response));
	rc = fp_ns_get_nxt(hba_num, fd, start_did, response, resp_len);
	if (rc > 0) {
		unsigned char *pn, *spn, *nn, *snn, *fc4_words;
		uint64_t fc4[5];
		int spn_length, snn_length, i;

		printf("GA_NXT length %d\n", resp_len);
		rport->rport = -1;
		rport->did = 0;
		rport->wwpn = 0;
		rport->wwnn = 0;
		if (resp_len < 20) {
			fprintf(stderr, "host%d: GA_NXT response len %d\n",
				hba_num, (int)resp_len);
			return -ECOMM;
		}
		rport->hba = hba_num;
		rport->did = ((response[17] << 16) & 0xff0000) |
			((response[18] << 8) & 0x00ff00) |
			(response[19] & 0x0000ff);
		resp_len -= 20;
		if (resp_len < 8)
			return 0;
		pn = &response[20];
		rport->wwpn = ntoh64(pn);
		resp_len -= 8;
		if (resp_len < 256)
			return 0;
		spn_length = pn[8];
		printf("symbolic portname length %d\n", spn_length);
		spn = pn + 9;
		memset(rport->spn, 0, 256);
		memcpy(rport->spn, &response[29], response[28]);
		if (spn_length > 0)
			printf("symbolic portname '%s'\n", spn);
		resp_len -= 256;
		if (resp_len < 8)
			return 0;
		nn = pn + 8 + 256;
		rport->wwnn = ntoh64(nn);
		resp_len -= 8;
		if (resp_len < 256)
			return 0;
		snn_length = nn[8];
		snn = nn + 9;
		printf("symbolic nodename length %d\n", snn_length);
		memset(rport->snn, 0, 256);
		memcpy(rport->snn, snn, snn_length);
		if (snn_length > 0)
			printf("symbolic nodename '%s'\n", snn);
		resp_len -= 256;
		fc4_words = nn + 8 + 256 + 28;
		fc4[0] = ntoh64(fc4_words);
		fc4_words += 8;
		fc4[1] = ntoh64(fc4_words);
		fc4_words += 8;
		fc4[2] = ntoh64(fc4_words);
		fc4_words += 8;
		fc4[3] = ntoh64(fc4_words);
		printf("FC-4 types:\n");
		for (i = 0; i < 4; i++)
			printf("\t%016llx\n", fc4[i]);

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
		return -ENXIO;
	}

	sprintf(bsg_dev, "/dev/bsg/rport-%d:0-%d", hba_num, wka_num);
	wka_fd = open(bsg_dev, O_RDWR);
	if (wka_fd < 0) {
		fprintf(stderr, "host%d: Cannot open bsg device %s: %s\n",
			hba_num, bsg_dev, strerror(errno));
		return -ENODEV;
	}

	rport = malloc(sizeof(struct rport_type_t));
	memset(rport, 0x0, sizeof(struct rport_type_t));
	did = hba_did;
	do {
		rc = fp_lookup_next_port(fp_hba, wka_fd, did, rport);
		if (rc < 0) {
			fprintf(stderr, "host%d: failed to lookup port %06lx\n",
				hba_num, did);
			break;
		}
		printf("host %06lx: found rport %06lx nn-0x%08llx:pn-0x%08llx\n",
		       hba_did, rport->did, rport->wwnn, rport->wwpn);
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
