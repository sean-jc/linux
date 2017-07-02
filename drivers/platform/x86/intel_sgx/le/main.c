// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

#include <asm/sgx.h>
#include <asm/sgx_arch.h>
#include <asm/sgx_le.h>
#include <linux/string.h>
#include <linux/types.h>
#include <uapi/asm/sgx.h>
#include "main.h"

static void *start_launch_enclave(void)
{
	struct sgx_enclave_create create_ioc;
	struct sgx_enclave_add_page add_ioc;
	struct sgx_enclave_init init_ioc;
	struct sgx_secs secs;
	struct sgx_secinfo secinfo;
	unsigned long blob_base;
	unsigned long blob_size;
	unsigned long offset;
	int rc;

	memset(&secs, 0, sizeof(secs));
	memset(&secinfo, 0, sizeof(secinfo));

	secs.ssaframesize = 1;
	secs.attributes = SGX_ATTR_MODE64BIT | SGX_ATTR_EINITTOKENKEY;
	secs.xfrm = 3;

	blob_base = (unsigned long)&sgx_le_blob;
	blob_size = (unsigned long)&sgx_le_blob_end - blob_base;

	for (secs.size = 4096; secs.size < blob_size; )
		secs.size <<= 1;

	secs.base = (unsigned long)sgx_sys_mmap(SGX_LE_DEV_FD, secs.size);
	if (secs.base == (unsigned long)MAP_FAILED)
		goto out;

	create_ioc.src = (unsigned long)&secs;
	rc = sgx_sys_ioctl(SGX_LE_DEV_FD, SGX_IOC_ENCLAVE_CREATE, &create_ioc);
	if (rc)
		goto out;

	add_ioc.secinfo = (unsigned long)&secinfo;
	add_ioc.mrmask = 0xFFFF;

	for (offset = 0; offset < blob_size; offset += 0x1000) {
		if (!offset)
			secinfo.flags = SGX_SECINFO_TCS;
		else
			secinfo.flags = SGX_SECINFO_REG | SGX_SECINFO_R |
					SGX_SECINFO_W | SGX_SECINFO_X;

		add_ioc.addr = secs.base + offset;
		add_ioc.src = blob_base + offset;

		rc = sgx_sys_ioctl(SGX_LE_DEV_FD, SGX_IOC_ENCLAVE_ADD_PAGE,
				   &add_ioc);
		if (rc)
			goto out;
	}

	init_ioc.addr = secs.base;
	init_ioc.sigstruct = (uint64_t)&sgx_le_ss;
	rc = sgx_sys_ioctl(SGX_LE_DEV_FD, SGX_IOC_ENCLAVE_INIT, &init_ioc);
	if (rc)
		goto out;

	return (void *)secs.base;
out:
	return NULL;
}

static int read_input(void *data, unsigned int len)
{
	uint8_t *ptr = (uint8_t *)data;
	long i;
	long ret;

	for (i = 0; i < len; ) {
		ret = sgx_sys_read(&ptr[i], len - i);
		if (ret < 0)
			return ret;

		i += ret;
	}

	return 0;
}

static int write_token(const struct sgx_einittoken *token)
{
	const uint8_t *ptr = (const uint8_t *)token;
	long i;
	long ret;

	for (i = 0; i < sizeof(*token); ) {
		ret = sgx_sys_write(&ptr[i], sizeof(*token) - i);
		if (ret < 0)
			return ret;

		i += ret;
	}

	return 0;
}

void _start(void)
{
	struct sgx_launch_request req;
	struct sgx_einittoken token;
	void *entry;

	sgx_sys_close(SGX_LE_EXE_FD);
	entry = start_launch_enclave();
	sgx_sys_close(SGX_LE_DEV_FD);
	if (!entry)
		sgx_sys_exit(1);

	for ( ; ; ) {
		memset(&req, 0, sizeof(req));
		memset(&token, 0, sizeof(token));

		if (read_input(&req, sizeof(req)))
			sgx_sys_exit(1);

		sgx_get_token(&req, entry, &token);

		if (write_token(&token))
			sgx_sys_exit(1);
	}

	__builtin_unreachable();
}
