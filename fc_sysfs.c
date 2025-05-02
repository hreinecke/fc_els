// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025 Hannes Reinecke, SUSE
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>

#include "fc_sysfs.h"

/*
 * Lookup specified adapter from sysfs
 */
fc_fid_t fp_find_hba(int hba_num)
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

int fc_rport_get_attr(const char *rport, const char *attr,
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

int fp_find_did(int hba_num, fc_fid_t did)
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
			continue;
		}

		count = fc_rport_get_attr(dentry->d_name, "port_id",
					  attrvalue, sizeof(attrvalue));
		if (count < 0) {
			break;
		}

		tmp_did = strtoull(attrvalue, &endptr, 16);
		if (attrvalue == endptr) {
			fprintf(stderr, "%s: Invalid Port ID %s\n",
				dentry->d_name, attrvalue);
			tmp_did = (fc_fid_t)0;
		}
		if (did == tmp_did) {
			rport_num = tmp_rport;
			break;
		}
	}
	closedir(dirp);
	return rport_num;
}
