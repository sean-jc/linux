/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD Secure Encrypted Virtualization (SEV) guest driver interface
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 */

#ifndef __LINUX_SEV_GUEST_H_
#define __LINUX_SEV_GUEST_H_

#include <linux/types.h>

enum vmgexit_type {
	GUEST_REQUEST,
	EXT_GUEST_REQUEST,

	GUEST_REQUEST_MAX
};

/*
 * The secrets page contains 96-bytes of reserved field that can be used by
 * the guest OS. The guest OS uses the area to save the message sequence
 * number for each VMPL level.
 *
 * See the GHCB spec section Secret page layout for the format for this area.
 */
struct secrets_os_area {
	u32 msg_seqno_0;
	u32 msg_seqno_1;
	u32 msg_seqno_2;
	u32 msg_seqno_3;
	u64 ap_jump_table_pa;
	u8 rsvd[40];
	u8 guest_usage[32];
} __packed;

#define VMPCK_KEY_LEN		32

/* See the SNP spec secrets page layout section for the structure */
struct snp_secrets_page_layout {
	u32 version;
	u32 imiEn	: 1,
	    rsvd1	: 31;
	u32 fms;
	u32 rsvd2;
	u8 gosvw[16];
	u8 vmpck0[VMPCK_KEY_LEN];
	u8 vmpck1[VMPCK_KEY_LEN];
	u8 vmpck2[VMPCK_KEY_LEN];
	u8 vmpck3[VMPCK_KEY_LEN];
	struct secrets_os_area os_area;
	u8 rsvd3[3840];
} __packed;

/*
 * The error code when the data_npages is too small. The error code
 * is defined in the GHCB specification.
 */
#define SNP_GUEST_REQ_INVALID_LEN	0x100000000ULL

struct snp_guest_request_data {
	unsigned long req_gpa;
	unsigned long resp_gpa;
	unsigned long data_gpa;
	unsigned int data_npages;
};

struct snp_guest_platform_data {
	u8 vmpck_id;
	char vmpck[VMPCK_KEY_LEN];
};

#ifdef CONFIG_AMD_MEM_ENCRYPT
int snp_issue_guest_request(int vmgexit_type, struct snp_guest_request_data *input,
			    unsigned long *fw_err);
u64 snp_msg_seqno(void);
#else

static inline int snp_issue_guest_request(int type, struct snp_guest_request_data *input,
					  unsigned long *fw_err)
{
	return -ENODEV;
}
static inline u64 snp_msg_seqno(void) { return 0; }

#endif /* CONFIG_AMD_MEM_ENCRYPT */
#endif /* __LINUX_SEV_GUEST_H__ */
