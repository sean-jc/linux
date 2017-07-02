// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Derived from TinyCrypt CMAC implementation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

#ifndef MAIN_H
#define MAIN_H

#define RAND_NR_TRIES 10

int sgx_ereport(const void *target_info, const void *report_data,
		void *report);
int sgx_egetkey(void *key_request, void *key);

#endif /* MAIN_H */
