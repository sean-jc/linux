// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

#include <linux/linkage.h>
#include <asm/export.h>
#include <asm/page_types.h>

	.section ".rodata","a"

GLOBAL(sgx_le_proxy)
	.incbin	"drivers/platform/x86/intel_sgx/le/sgx_le_proxy"
END(sgx_le_proxy)

GLOBAL(sgx_le_proxy_end)

GLOBAL(sgx_le_ss)
	.incbin	"drivers/platform/x86/intel_sgx/le/enclave/sgx_le.ss"
END(sgx_le_ss)
