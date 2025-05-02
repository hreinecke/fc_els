// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025 Hannes Reinecke, SUSE
 */

typedef uint32_t fc_fid_t;   /* fabric address */

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
