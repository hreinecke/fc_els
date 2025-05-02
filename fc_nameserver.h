#ifndef _FC_NAMESERVER_H
#define _FC_NAMESERVER_H

typedef uint64_t fc_wwn_t;    /* world-wide name */
typedef uint32_t fc_fid_t;   /* fabric address */

/* Check if it is WKA according to FC-FS-3 Rev 1.00 Clause 11 Table 30 */
#define FCID_IS_WKA(i) ((((i) >= 0xfffc01) && ((i) <= 0xfffcfe)) || \
			(((i) >= 0xfffff0) && ((i) <= 0xffffff)))

#define FC_WKA_FABRIC_CONTROLLER ((fc_fid_t)0xfffffd)
#define FC_WKA_DIRECTORY_SERVICE ((fc_fid_t)0xfffffc)
#define FC_WKA_MANAGEMENT_SERVICE ((fc_fid_t)0xfffffa)

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

struct rport_type_t {
	int hba;
	int rport;
	fc_fid_t did;
	fc_wwn_t wwpn;
	fc_wwn_t wwnn;
};

int fc_rport_get_attr(const char *rport, const char *attr,
		      char *value, int value_len);
fc_fid_t fp_lookup_target_by_wwpn(int hba_num, unsigned long long wwpn);
int fp_lookup_next_port(int hba_num, int fd, fc_fid_t start_did,
			struct rport_type_t *rport);
fc_fid_t fp_find_hba(int hba_num);
int fp_find_did(int hba_num, fc_fid_t did);

#endif
