// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

#ifndef MAIN_H
#define MAIN_H

#ifndef NULL
#define NULL ((void *)0)
#endif

#define MAP_FAILED ((void *)-1)

extern unsigned char sgx_le_blob[];
extern unsigned char sgx_le_blob_end[];
extern unsigned char sgx_le_ss[];

void sgx_get_token(struct sgx_launch_request *req, void *entry,
		   struct sgx_einittoken *token);
long sgx_sys_read(void *buf, unsigned long count);
long sgx_sys_write(const void *buf, unsigned long count);
long sgx_sys_close(long fd);
long sgx_sys_mmap(long fd, unsigned long size);
long sgx_sys_ioctl(long fd, unsigned long cmd, void *arg);
long sgx_sys_exit(long status);

#endif /* MAIN_H */
