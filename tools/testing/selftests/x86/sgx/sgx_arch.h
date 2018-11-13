/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2016-18 Intel Corporation.
 */

#ifndef SGX_ARCH_H
#define SGX_ARCH_H

#include <stdint.h>

enum sgx_attribute {
	SGX_ATTR_DEBUG		= 0x02,
	SGX_ATTR_MODE64BIT	= 0x04,
	SGX_ATTR_PROVISIONKEY	= 0x10,
	SGX_ATTR_EINITTOKENKEY	= 0x20,
};

#define SGX_ATTR_RESERVED_MASK 0xFFFFFFFFFFFFFFC9L

#define SGX_SECS_RESERVED1_SIZE 24
#define SGX_SECS_RESERVED2_SIZE 32
#define SGX_SECS_RESERVED3_SIZE 96
#define SGX_SECS_RESERVED4_SIZE 3836

struct sgx_secs {
	uint64_t size;
	uint64_t base;
	uint32_t ssaframesize;
	uint32_t miscselect;
	uint8_t reserved1[SGX_SECS_RESERVED1_SIZE];
	uint64_t attributes;
	uint64_t xfrm;
	uint32_t mrenclave[8];
	uint8_t reserved2[SGX_SECS_RESERVED2_SIZE];
	uint32_t mrsigner[8];
	uint8_t	reserved3[SGX_SECS_RESERVED3_SIZE];
	uint16_t isvvprodid;
	uint16_t isvsvn;
	uint8_t reserved4[SGX_SECS_RESERVED4_SIZE];
};

#define SGX_SECINFO_PERMISSION_MASK	0x0000000000000007L
#define SGX_SECINFO_PAGE_TYPE_MASK	0x000000000000FF00L
#define SGX_SECINFO_RESERVED_MASK	0xFFFFFFFFFFFF00F8L

enum sgx_page_type {
	SGX_PAGE_TYPE_SECS	= 0x00,
	SGX_PAGE_TYPE_TCS	= 0x01,
	SGX_PAGE_TYPE_REG	= 0x02,
	SGX_PAGE_TYPE_VA	= 0x03,
	SGX_PAGE_TYPE_TRIM	= 0x04,
};

enum sgx_secinfo_flags {
	SGX_SECINFO_R		= 0x01,
	SGX_SECINFO_W		= 0x02,
	SGX_SECINFO_X		= 0x04,
	SGX_SECINFO_SECS	= (SGX_PAGE_TYPE_SECS << 8),
	SGX_SECINFO_TCS		= (SGX_PAGE_TYPE_TCS << 8),
	SGX_SECINFO_REG		= (SGX_PAGE_TYPE_REG << 8),
	SGX_SECINFO_TRIM	= (SGX_PAGE_TYPE_TRIM << 8),
};

struct sgx_secinfo {
	uint64_t flags;
	uint64_t reserved[7];
} __attribute__((aligned(64)));

#define SGX_MODULUS_SIZE 384

struct sgx_sigstruct_header {
	uint64_t header1[2];
	uint32_t vendor;
	uint32_t date;
	uint64_t header2[2];
	uint32_t swdefined;
	uint8_t reserved1[84];
};

struct sgx_sigstruct_body {
	uint32_t miscselect;
	uint32_t miscmask;
	uint8_t reserved2[20];
	uint64_t attributes;
	uint64_t xfrm;
	uint8_t attributemask[16];
	uint8_t mrenclave[32];
	uint8_t reserved3[32];
	uint16_t isvprodid;
	uint16_t isvsvn;
} __attribute__((__packed__));

struct sgx_sigstruct {
	struct sgx_sigstruct_header header;
	uint8_t modulus[SGX_MODULUS_SIZE];
	uint32_t exponent;
	uint8_t signature[SGX_MODULUS_SIZE];
	struct sgx_sigstruct_body body;
	uint8_t reserved4[12];
	uint8_t q1[SGX_MODULUS_SIZE];
	uint8_t q2[SGX_MODULUS_SIZE];
};

struct sgx_sigstruct_payload {
	struct sgx_sigstruct_header header;
	struct sgx_sigstruct_body body;
};

#endif /* SGX_ARCH_H */
