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

#ifdef CONFIG_AMD_MEM_ENCRYPT
int snp_issue_guest_request(int vmgexit_type, struct snp_guest_request_data *input,
			    unsigned long *fw_err);
#else

static inline int snp_issue_guest_request(int type, struct snp_guest_request_data *input,
					  unsigned long *fw_err)
{
	return -ENODEV;
}

#endif /* CONFIG_AMD_MEM_ENCRYPT */
#endif /* __LINUX_SEV_GUEST_H__ */
