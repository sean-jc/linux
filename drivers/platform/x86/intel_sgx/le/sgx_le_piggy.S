// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

#include <linux/linkage.h>
#include <asm/page_types.h>

	.section ".rodata","a"
	.balign PAGE_SIZE

GLOBAL(sgx_le_blob)
	.incbin	"drivers/platform/x86/intel_sgx/le/enclave/sgx_le.bin"
END(sgx_le_blob)

GLOBAL(sgx_le_blob_end);

GLOBAL(sgx_le_ss)
	.incbin	"drivers/platform/x86/intel_sgx/le/enclave/sgx_le.ss"
END(sgx_le_ss)
