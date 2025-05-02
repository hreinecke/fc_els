/*
 * Copyright(c) 2010 Intel Corporation. All rights reserved.
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
 * Maintained at www.Open-FCoE.org
 */

/*
 * FCPing - FC fabric diagnostic.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <malloc.h>
#include <limits.h>
#include <signal.h>
#include <dirent.h>
#include <syslog.h>
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

typedef unsigned long long fc_wwn_t;    /* world-wide name */
typedef u_int32_t fc_fid_t;   /* fabric address */

static const char *cmdname = "fcping";

#define FC_MAX_PAYLOAD  2112UL	/* Max FC payload */
#define MAX_SENSE_LEN	96	/* SCSI_SENSE_BUFFERSIZE */
/* FC ELS ECHO Command takes 4 bytes */
#define FP_LEN_ECHO	sizeof(u_int32_t)
/* default max ping data length, excluding 4 bytes of ELS ECHO command */
#define FP_LEN_MAX	(FC_MAX_PAYLOAD - FP_LEN_ECHO)
#define FP_LEN_MIN	4	/* fcping needs 4 bytes as sequence number */
#define FP_LEN_DEF	32	/* default ping payload length */
#define FP_LEN_PAD	32	/* extra length for response */

/* Check if it is WKA accoriding to FC-FS-3 Rev 1.00 Clause 11 Table 30 */
#define FCID_IS_WKA(i) ((((i) >= 0xfffc01) && ((i) <= 0xfffcfe)) || \
			(((i) >= 0xfffff0) && ((i) <= 0xffffff)))

#define FC_WKA_FABRIC_CONTROLLER ((fc_fid_t)0xfffffd)
#define FC_WKA_DIRECTORY_SERVICE ((fc_fid_t)0xfffffc)

static void
fp_usage()
{
	fprintf(stderr,
		"Usage: %s [ -fqx ] [ -i <interval> ] [ -c <count> ] -h <hba> "
		"[ -s <size> ] { -F <FC-ID> | -P <WWPN> | -N <WWNN> | -R <rport> }\n"
		"  flags:\n"
		"     -f:            Flood ping\n"
		"     -q:            Quiet! just print summary\n"
		"     -x:            Hex dump of responses\n"
		"     -i <interval>: Wait <interval> seconds between each ping\n"
		"     -c <count>:    Stop after sending <count> pings\n"
		"     -h <hba>:      eth<n>, MAC address, WWPN, or FC-ID of the HBA\n"
		"     -s <size>:     Byte-length of ping request payload (max %lu)\n"
		"     -F <FC-ID>:    Destination port ID\n"
		"     -P <WWPN>:     Destination world-wide port name\n"
		"     -N <WWNN>:     Destination world-wide node name\n"
		"     -R <rport>:    FC remote-port number\n",
		cmdname, FP_LEN_MAX);

	fprintf(stderr, "\nNote that the default maximum FC payload allowed "
		"is %lu bytes and the default maxmaxium fcping payload, "
		"i.e., the FC ELS ECHO data, allowed is %lu "
		"bytes.\n",
		FC_MAX_PAYLOAD, FP_LEN_MAX);

	exit(1);
}

static fc_fid_t fp_did;
static fc_wwn_t fp_port_wwn;
static fc_wwn_t fp_node_wwn;
static int fp_hex;
static int fp_hba = -1;	/* number of fc_host to be used */
static int fp_port_num = -1;
static int fp_debug;

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

static void sa_log_func(const char *func, const char *format, ...);
static void sa_log_err(int, const char *func, const char *format, ...);
static void sa_log_output(const char *buf);

/*
 * Log message.
 */
#define SA_LOG(...)						\
	do { sa_log_func(__func__, __VA_ARGS__); } while (0)

#define SA_LOG_ERR(error, ...)					\
	do { sa_log_err(error, NULL, __VA_ARGS__); } while (0)

/*
 * Logging exits.
 */
#define SA_LOG_EXIT(...)						\
	do {	sa_log_func(__func__, __VA_ARGS__);			\
		if (fp_debug)						\
			sa_log_func(__func__,				\
				    "Exiting at %s:%d", __FILE__, __LINE__); \
		exit(1);						\
	} while (0)

#define SA_LOG_ERR_EXIT(error, ...)					\
	do {	sa_log_func(__func__, __VA_ARGS__);			\
		if (fp_debug)						\
			sa_log_err(error, __func__,			\
				   "Exiting at %s:%d", __FILE__, __LINE__); \
		else							\
			sa_log_err(error, NULL, NULL);			\
		exit(1);						\
	} while (0)

#define SA_LOG_BUF_LEN  200     /* on-stack line buffer size */

/*
 * log with a variable argument list.
 */
static void
sa_log_va(const char *func, const char *format, va_list arg)
{
	size_t len;
	size_t flen;
	int add_newline;
	char sa_buf[SA_LOG_BUF_LEN];
	char *bp;

	/*
	 * If the caller didn't provide a newline at the end, we will.
	 */
	len = strlen(format);
	add_newline = 0;
	if (!len || format[len - 1] != '\n')
		add_newline = 1;
	bp = sa_buf;
	len = sizeof(sa_buf);
	if (func) {
		flen = snprintf(bp, len, "%s: ", func);
		len -= flen;
		bp += flen;
	}
	flen = vsnprintf(bp, len, format, arg);
	if (add_newline && flen < len) {
		bp += flen;
		*bp++ = '\n';
		*bp = '\0';
	}
	sa_log_output(sa_buf);
}

/*
 * log with function name.
 */
static void
sa_log_func(const char *func, const char *format, ...)
{
	va_list arg;

	va_start(arg, format);
	if (fp_debug)
		sa_log_va(func, format, arg);
	else
		sa_log_va(NULL, format, arg);
	va_end(arg);
}

/*
 * log with error number.
 */
static void
sa_log_err(int error, const char *func, const char *format, ...)
{
	va_list arg;
	char buf[SA_LOG_BUF_LEN];

	strerror_r(error, buf, sizeof(buf));
	sa_log_func(func, "errno=%d %s", error, buf);
	if (format) {
		va_start(arg, format);
		sa_log_va(func, format, arg);
		va_end(arg);
	}
}

static void
sa_log_output(const char *buf)
{
	fprintf(stderr, "%s", buf);
	fflush(stderr);
}

static char *
sa_hex_format(char *buf, size_t buflen,
	      const unsigned char *data, size_t data_len,
	      unsigned int group_len, char *inter_group_sep)
{
	size_t rlen, tlen;
	char *bp, *sep;
	unsigned int i;

	rlen = buflen;
	bp = buf;
	sep = "";
	for (i = 0; rlen > 0 && i < data_len; ) {
		tlen = snprintf(bp, rlen, "%s%2.2x", sep, data[i]);
		rlen -= tlen;
		bp += tlen;
		i++;
		sep = (i % group_len) ? "" : inter_group_sep;
	}
	return buf;
}

/*
 * Hex dump buffer to file.
 */
static void sa_hex_dump(unsigned char *bp, size_t len, FILE *fp)
{
	char lbuf[120];
	size_t tlen;
	uint32_t offset = 0;

	while (len > 0) {
		tlen = 16;  /* bytes per line */
		if (tlen > len)
			tlen = len;
		sa_hex_format(lbuf, sizeof(lbuf), bp, tlen, 4, " ");
		fprintf(fp, "%6x %s\n", offset, lbuf);
		offset += tlen;
		len -= tlen;
		bp += tlen;
	}
}

/*
 * Handle WWN/MAC arguments
 */
static fc_wwn_t
fp_parse_wwn(const char *arg, char *msg, uint32_t scheme, uint32_t port)
{
	char *endptr;
	fc_wwn_t wwn;

	wwn = strtoull(arg, &endptr, 16);
	if (*endptr != '\0')
		wwn = (fc_wwn_t)-1;

	return wwn;
}

/*
 * Handle options.
 */
static void
fp_options(int argc, char *argv[])
{
	int opt;
	char *endptr;
	int targ_spec = 0;

	if (argc <= 1)
		fp_usage();

	while ((opt = getopt(argc, argv, "?h:qs:xF:P:N:R:")) != -1) {
		switch (opt) {
		case 'h':
			fp_hba = (int)strtoul(optarg, &endptr, 10);
			if (*endptr != '\0')
				SA_LOG_EXIT("bad hba number %s\n", optarg);
			break;
		case 'x':
			fp_hex = 1;
			break;

			/*
			 * -F specifies the target FC_ID.
			 */
		case 'F':
			fp_did = strtoull(optarg, &endptr, 16);
			if (*endptr != '\0')
				SA_LOG_EXIT("bad target FC_ID %s\n", optarg);
			targ_spec++;
			break;

			/*
			 * The -P and -N flags take a world-wide name
			 * in hex, or an ethernet addr, or an etherhost
			 * entry from /etc/ethers.
			 */
		case 'N':
			fp_node_wwn = fp_parse_wwn(optarg, "Node", 1, 0);
			targ_spec++;
			break;

		case 'P':
			fp_port_wwn = fp_parse_wwn(optarg, "Port", 2, 0);
			targ_spec++;
			break;
		case 'R':
			fp_port_num = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0')
				SA_LOG_EXIT("bad rport number %s\n", optarg);
			targ_spec++;
			break;

		case '?':
		default:
			fp_usage();	/* exits */
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (fp_hba == -1)
		SA_LOG_EXIT("FC HBA not specified");

	if (targ_spec > 1)
		SA_LOG_EXIT("too many targets specified;"
			    " only one is allowed.");
	else if (targ_spec == 0)
		return;

	return;
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
		printf("HBA %d not found\n", hba_num);
		return did;
	}
	count = read(fd, attrvalue, sizeof(attrvalue));
	if (count < 0) {
		SA_LOG_ERR(errno, "Cannot read from %s", attrpath);
		return did;
	}
	close(fd);
	did = strtoull(attrvalue, &endptr, 16);
	if (attrvalue == endptr) {
		printf("Invalid Port ID %s on HBA %d\n", attrvalue, hba_num);
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
	char attrpath[256], attrvalue[512], *endptr;
	fc_fid_t tmp_did = (fc_fid_t)0;
	int fd = -1;
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
			printf("%s: invalid bus number %d\n",
			       dentry->d_name, tmp_bus);
			continue;
		}

		sprintf(attrpath, "/sys/class/fc_remote_ports/%s/port_id",
			dentry->d_name);
		fd = open(attrpath, O_RDONLY);
		if (fd < 0) {
			SA_LOG_ERR(errno, "Failed to open %s", attrpath);
			break;
		}
		count = read(fd, attrvalue, sizeof(attrvalue));
		if (count < 0) {
			SA_LOG_ERR(errno, "Cannot read from %s", attrpath);
			break;
		}
		close(fd);
		tmp_did = strtoull(attrvalue, &endptr, 16);
		if (attrvalue == endptr) {
			SA_LOG("Invalid Port ID %s\n", attrvalue);
			tmp_did = (fc_fid_t)0;
		}
		if (did == tmp_did) {
			rport_num = tmp_rport;
			printf("Port ID %lx found at rport %d:0-%d\n",
			       (unsigned long)did, hba_num, rport_num);
			break;
		}
	}
	closedir(dirp);
	return rport_num;
}

/*
 * Lookup ID from port name or node name.
 */
static int
fp_ns_get_id(int hba_num, uint32_t op, fc_wwn_t wwn,
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

	wka_port = fp_find_did(hba_num, FC_WKA_DIRECTORY_SERVICE);
	if (wka_port < 0) {
		printf("No remote port found for WKA %06lx\n",
		       (unsigned long)FC_WKA_DIRECTORY_SERVICE);
		return -ENXIO;
	}

	sprintf(bsg_dev, "/dev/bsg/rport-%d:0-%d", hba_num, wka_port);
	fp_rport_fd = open(bsg_dev, O_RDWR);
	if (fp_rport_fd < 0) {
		printf("Cannot open bsg device %s: %s\n",
		       bsg_dev, strerror(errno));
		return -1;
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
		if (op == FC_NS_GID_PN)
			printf("GID_PN error: %s\n", strerror(errno));
		if (op == FC_NS_GID_NN)
			printf("GID_NN error: %s\n", strerror(errno));
		close(fp_rport_fd);
		return rc;
	}

	cmd = ((response[8]<<8) | response[9]) & 0xffff;
	if (cmd != FC_FS_ACC) {
		if (cmd == FC_FS_RJT) {
			if (op == FC_NS_GID_PN)
				printf("GID_PN rejected, reason %02x/%02x\n",
				       response[13], response[14]);
			if (op == FC_NS_GID_NN)
				printf("GID_NN rejected, reason %02x/%02x\n",
				       response[13], response[14]);
		} else {
			if (op == FC_NS_GID_PN)
				printf("GID_PN result %x\n", cmd);
			if (op == FC_NS_GID_NN)
				printf("GID_NN result %x\n", cmd);
		}
		close(fp_rport_fd);
		return 0;
	}

	actual_len = reply.reply_payload_rcv_len;
	if (actual_len < *resp_len)
		*resp_len = actual_len;

	close(fp_rport_fd);
	return 0;
}

static int
fp_ns_get_nxt(int hba_num, fc_fid_t did, char *response, size_t *resp_len)
{
	char bsg_dev[80];
	int wka_num = -1;
	struct ct_ga_nxt {
		struct fc_ct_hdr hdr;
		uint8_t reserved;
		uint8_t port_id[3];
	} ct;
	struct fc_bsg_request cdb;
	struct fc_bsg_reply reply;
	struct sg_io_v4 sg_io;
	size_t actual_len;
	int fp_rport_fd;
	int cmd, rc = 0;

	wka_num = fp_find_did(hba_num, FC_WKA_DIRECTORY_SERVICE);
	if (wka_num < 0) {
		printf("No remote port found for WKA %06lx\n",
		       (unsigned long)FC_WKA_DIRECTORY_SERVICE);
		return -ENXIO;
	}

	sprintf(bsg_dev, "/dev/bsg/rport-%d:0-%d", hba_num, wka_num);
	fp_rport_fd = open(bsg_dev, O_RDWR);
	if (fp_rport_fd < 0) {
		printf("Cannot open bsg device %s: %s\n",
		       bsg_dev, strerror(errno));
		return -1;
	}
	memset((char *)&cdb, 0, sizeof(cdb));
	memset(&ct, 0, sizeof(ct));
	ct.hdr.ct_rev = FC_CT_REV;
	ct.hdr.ct_fs_type = FC_FST_DIR;
	ct.hdr.ct_fs_subtype = FC_NS_SUBTYPE;
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

	rc = ioctl(fp_rport_fd, SG_IO, &sg_io);
	if (rc < 0) {
		printf("GA_NXT error: %s\n", strerror(errno));
		close(fp_rport_fd);
		return rc;
	}

	cmd = ((response[8]<<8) | response[9]) & 0xffff;
	if (cmd != FC_FS_ACC) {
		if (cmd == FC_FS_RJT) {
			printf("GA_NXT rejected, reason %02x/%02x\n",
			       response[13], response[14]);
		} else {
			printf("GA_NXT result %x\n", cmd);
		}
		close(fp_rport_fd);
		return 0;
	}

	actual_len = reply.reply_payload_rcv_len;
	if (actual_len < *resp_len)
		*resp_len = actual_len;

	close(fp_rport_fd);
	return 0;
}

static fc_fid_t
fp_lookup_next_port(int hba_num, fc_fid_t start_did)
{
	char response[256];
	size_t resp_len;
	int rc;
	fc_fid_t did = start_did;

	resp_len = sizeof(response);
	memset(&response, 0, sizeof(response));
	rc = fp_ns_get_nxt(hba_num, start_did, response, &resp_len);
	if (rc == 0) {
		did = ((response[17] << 16) & 0xff0000) |
			((response[18] << 8) & 0x00ff00) |
			(response[19] & 0x0000ff);
	}

	return did;
}

fc_fid_t
fp_lookup_target_by_wwpn(int hba_num, unsigned long long wwpn)
{
	char response[256];
	size_t resp_len;
	int rc;
	fc_fid_t did = (fc_fid_t)0;

	if (wwpn == 0) {
		SA_LOG("Invalid wwpn 0x%llx", wwpn);
		return did;
	}
	resp_len = sizeof(response);
	memset(&response, 0, sizeof(response));
	rc = fp_ns_get_id(hba_num, FC_NS_GID_PN, wwpn,
			  response, &resp_len);
	if (rc == 0) {
		did = ((response[17] << 16) & 0xff0000) |
			((response[18] << 8) & 0x00ff00) |
			(response[19] & 0x0000ff);
		printf("GID_PN found did %06x\n", did);
	} else
		SA_LOG("cannot find fcid of destination @ wwpn 0x%llX", wwpn);

	return did;
}

fc_fid_t
fp_lookup_target_by_wwnn(int hba_num, unsigned long long wwnn)
{
	char response[256];
	size_t resp_len;
	int rc;
	fc_fid_t did = (fc_fid_t)0;

	if (wwnn == 0) {
		SA_LOG("Invalid wwnn 0x%llx", wwnn);
		return -EINVAL;
	}
	resp_len = sizeof(response);
	memset(&response, 0, sizeof(response));
	rc = fp_ns_get_id(hba_num, FC_NS_GID_NN, wwnn,
			  response, &resp_len);
	if (rc == 0) {
		did = ((response[17] << 16) & 0xff0000) |
			((response[18] << 8) & 0x00ff00) |
			(response[19] & 0x0000ff);
		printf("GID_NN found did %06x\n", did);
	} else
		SA_LOG("cannot find fcid of destination @ wwnn 0x%llX", wwnn);

	return did;
}

static fc_fid_t
fp_lookup_target_by_rport(unsigned int hba_num, unsigned int rport)
{
	DIR *dirp;
	struct dirent *dentry;
	int tmp_hba, tmp_bus, tmp_rport, found = 0;
	char attrpath[256], attrvalue[512], *endptr;
	fc_fid_t did = (fc_fid_t)0;
	int fd = -1;
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
			printf("%s: invalid bus number %d\n",
			       dentry->d_name, tmp_bus);
			continue;
		}
		if (tmp_rport == rport) {
			found++;
			break;
		}
	}
	closedir(dirp);
	if (found) {
		sprintf(attrpath, "/sys/class/fc_remote_ports/%s/port_id",
			dentry->d_name);
		fd = open(attrpath, O_RDONLY);
		if (fd < 0) {
			SA_LOG_ERR(errno, "Failed to open %s", attrpath);
			goto out;
		}
		count = read(fd, attrvalue, sizeof(attrvalue));
		if (count < 0) {
			SA_LOG_ERR(errno, "Cannot read from %s", attrpath);
			goto out;
		}
		close(fd);
		did = strtoull(attrvalue, &endptr, 16);
		if (attrvalue == endptr) {
			SA_LOG("Invalid Port ID %s\n", attrvalue);
			did = (fc_fid_t)0;
		}
		printf("rport %d:0-%d: Found port id 0x%lx\n",
		       hba_num, rport, (unsigned long)did);
	}
out:
	return did;
}

/*
 * ELS_ECHO request format being used.
 * Put a sequence number in the payload, followed by the pattern.
 */
struct fcping_echo {
	uint8_t     fe_op;              /* opcode */
	uint8_t     fe_resvd[3];           /* reserved, must be zero */
	uint32_t    fe_seq;             /* sequence number */
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
		SA_LOG_ERR_EXIT(errno, "calloc %d bytes failed", len);
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
		printf("Cannot open bsg device %s: %s\n",
		       bsg_dev, strerror(errno));
		return -1;
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
	sg_io.timeout = 20000;
	memset(sense, 0, sizeof(sense));

	rc = ioctl(fp_rport_fd, SG_IO, &sg_io);
	if (rc >= 0) {
		*resp_len = sg_io.din_xfer_len - sg_io.din_resid;
		rc = 0;
	}
	close(fp_rport_fd);
	return 0;
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

	fp_buf = fp_buf_setup(fp_len);

	/* send ELS ECHO frame and receive */
	printf("Send ELS ECHO did %06x: ", did);
	rc = send_els_echo(hba_num, rport, fp_buf, fp_len, resp, &resp_len);
	if (rc) {
		printf("error %s\n", strerror(errno));
	} else {
		ep = (struct fcping_echo *) resp;
		if (ep->fe_op == ELS_LS_ACC) {
			if (memcmp((char *) ep + 1,
				   (char *) fp_buf + 1, fp_len - 1) == 0)
				printf("accepted\n");
			else {
				printf("accept data mismatches\n");
			}
		} else if (ep->fe_op == ELS_LS_RJT) {
			printf("rejected\n");
		} else {
			printf("op %x received", ep->fe_op);
		}
	}
	if (fp_hex) {
		printf("response length %u\n", resp_len);
		sa_hex_dump(resp, resp_len, stdout);
		printf("\n");
	}
	free(fp_buf);
	return rc;
}

int fp_ping_all_ports(int hba_num, fc_fid_t hba_did)
{
	fc_fid_t did;
	int rc = 0, rport;

	printf("Ping all ports on HBA %d\n", hba_num);
	did = fp_lookup_next_port(hba_num, hba_did);
	while (did && did != hba_did) {
		rport = fp_find_did(hba_num, did);
		if (rport < 0) {
			printf("No remote port found for port id %06x\n", did);
			rc++;
		} else {
			rc += fp_send_ping(hba_num, rport, did);
		}
		did = fp_lookup_next_port(hba_num, did);
	}
	return rc;
}
/*
 * Main.
 */
int main(int argc, char *argv[])
{
	fc_fid_t fp_hba_did;
	int fp_rport;
	int did;
	int rc = 1;

	fp_options(argc, argv);

	fp_hba_did = fp_find_hba(fp_hba);
	if (!fp_hba_did) {
		printf("HBA %d not found\n", fp_hba);
		return 1;
	}
	printf("Found HBA %d, port id %06x\n", fp_hba, fp_hba_did);

	if (fp_port_wwn)
		did = fp_lookup_target_by_wwpn(fp_hba, fp_port_wwn);
	if (fp_node_wwn)
		did = fp_lookup_target_by_wwnn(fp_hba, fp_node_wwn);
	if (fp_port_num != -1)
		did = fp_lookup_target_by_rport(fp_hba, fp_port_num);
	printf("HBA %d found port id %06x\n", fp_hba, did);
	if (did == 0) {
		rc = fp_ping_all_ports(fp_hba, fp_hba_did);
	} else {
		rc = fp_send_ping(fp_hba, fp_rport, did);
	}
	return rc;
}
