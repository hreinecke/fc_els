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
		fprintf(stderr, "host%d: No remote port found for WKA %06lx\n",
		       hba_num, (unsigned long)FC_WKA_DIRECTORY_SERVICE);
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

fc_fid_t
fp_lookup_target_by_wwpn(int hba_num, unsigned long long wwpn)
{
	char response[256];
	size_t resp_len;
	int rc;
	fc_fid_t did = (fc_fid_t)0;

	resp_len = sizeof(response);
	memset(&response, 0, sizeof(response));
	rc = fp_ns_get_id(hba_num, FC_NS_GID_PN, wwpn,
			  response, &resp_len);
	if (rc == 0 && resp_len > 19) {
		did = ((response[17] << 16) & 0xff0000) |
			((response[18] << 8) & 0x00ff00) |
			(response[19] & 0x0000ff);
	}

	return did;
}
