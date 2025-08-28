// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025 Hannes Reinecke, SUSE
 */

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

typedef uint32_t fc_fid_t;   /* fabric address */
typedef uint64_t fc_wwn_t;    /* world-wide name */

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

#define ntoh64(v) \
	((uint64_t)(v[0]) << 56) | ((uint64_t)(v[1]) << 48) |	\
	((uint64_t)(v[2]) << 40) | ((uint64_t)(v[3]) << 32) |	\
	((uint64_t)(v[4]) << 24) | ((uint64_t)(v[5]) << 16) |	\
	((uint64_t)(v[6]) <<  8) | ((uint64_t)(v[7]))

#define ntoh32(v) \
	((uint32_t)(v[0]) << 24) | ((uint32_t)(v[1]) << 16) |	\
	((uint32_t)(v[2]) <<  8) | ((uint32_t)(v[3]))

/**
 * fp_find_hba - return the FC ID of a FC HBA
 * @hba_num: sysfs number of the HBA to query
 *
 * Returns the FC ID of the HBA with sysfs number @hba_num
 * or 0 if no HBA was found.
 */
fc_fid_t fp_find_hba(int hba_num);

/**
 * fp_find_did - return the remote port number
 * @did: FC ID of the remote port
 *
 * Returns the sysfs rport number of a remote port
 * with FC ID @did or -1 if not found.
 */
int fp_find_did(int hba_num, fc_fid_t did);

/**
 * fc_rport_get_attr - read remote port sysfs attribute
 * @rport: sysfs path of the remote port
 * @attr: attribute name
 * @value: buffer for attribute value
 * @value_len: length of @value
 *
 * Reads the sysfs attribute @attr from sysfs path @rport
 * into the buffer @value with length @value_len.
 * Returns the number of bytes written to @value or -1
 * if an error occurred.
 */
int fc_rport_get_attr(const char *rport, const char *attr,
		      char *value, int value_len);
