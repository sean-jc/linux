// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
// Suresh Siddha <suresh.b.siddha@intel.com>
// Serge Ayoun <serge.ayoun@intel.com>
// Shay Katz-zamir <shay.katz-zamir@intel.com>

#ifndef _ASM_X86_SGX_PR_H
#define _ASM_X86_SGX_PR_H

#include <linux/printk.h>
#include <linux/ratelimit.h>

#undef pr_fmt
#define pr_fmt(fmt) "intel_sgx: " fmt

#endif /* _ASM_X86_SGX_PR_H */
