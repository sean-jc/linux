// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Derived from TinyCrypt CMAC implementation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

#include <asm/sgx.h>
#include <asm/sgx_arch.h>
#include <linux/types.h>
#include <uapi/asm/sgx.h>
#include "cmac_mode.h"
#include "main.h"

static bool rdrand_uint32(uint32_t *value)
{
	int i;

	for (i = 0; i < RAND_NR_TRIES; i++) {
		if (__builtin_ia32_rdrand32_step((unsigned int *)value))
			return true;
	}

	return false;
}

static bool sign_einittoken(struct sgx_einittoken *einittoken)
{
	struct sgx_keyrequest keyrequest __aligned(512);
	uint8_t launch_key[16] __aligned(16);
	struct tc_cmac_struct cmac_state;
	struct crypto_aes_ctx ctx;
	uint32_t *keyid_ptr;
	int i;

	memset(&ctx, 0, sizeof(ctx));

	/* Despite its misleading name, the only purpose of the keyid field is
	 * to add entropy to the token so that every token will have an unique
	 * CMAC.
	 */
	keyid_ptr = (uint32_t *)einittoken->keyid;

	for (i = 0; i < sizeof(einittoken->keyid) / 4; i++)
		if (!rdrand_uint32(&keyid_ptr[i]))
			return false;

	memset(&keyrequest, 0, sizeof(keyrequest));
	keyrequest.keyname = 0; /* LICENSE_KEY */
	memcpy(&keyrequest.keyid, &einittoken->keyid, sizeof(keyrequest.keyid));
	memcpy(&keyrequest.cpusvn, &(einittoken->cpusvnle),
	       sizeof(keyrequest.cpusvn));
	memcpy(&keyrequest.isvsvn, &(einittoken->isvsvnle),
	       sizeof(keyrequest.isvsvn));

	keyrequest.attributemask = ~SGX_ATTR_MODE64BIT;
	keyrequest.xfrmmask = 0;
	keyrequest.miscmask = 0xFFFFFFFF;

	einittoken->maskedmiscselectle &= keyrequest.miscmask;
	einittoken->maskedattributesle &= keyrequest.attributemask;
	einittoken->maskedxfrmle &= keyrequest.xfrmmask;

	if (sgx_egetkey(&keyrequest, launch_key))
		return false;

	tc_cmac_setup(&cmac_state, launch_key, &ctx);
	tc_cmac_init(&cmac_state);
	tc_cmac_update(&cmac_state, (const uint8_t *)&einittoken->payload,
		       sizeof(einittoken->payload));
	tc_cmac_final(einittoken->mac, &cmac_state);

	memset(launch_key, 0, sizeof(launch_key));

	return true;
}

static bool create_einittoken(uint8_t *mrenclave,
			      uint8_t *mrsigner,
			      uint64_t attributes,
			      uint64_t xfrm,
			      struct sgx_einittoken *einittoken)
{

	struct sgx_targetinfo tginfo __aligned(512);
	struct sgx_report report __aligned(512);
	uint8_t reportdata[64] __aligned(128);

	if (attributes & SGX_ATTR_RESERVED_MASK)
		return false;

	memset(&tginfo, 0, sizeof(tginfo));
	memset(reportdata, 0, sizeof(reportdata));
	memset(&report, 0, sizeof(report));

	if (sgx_ereport(&tginfo, reportdata, &report))
		return false;

	memset(einittoken, 0, sizeof(*einittoken));

	einittoken->payload.valid = 1;

	memcpy(einittoken->payload.mrenclave, mrenclave, 32);
	memcpy(einittoken->payload.mrsigner, mrsigner, 32);
	einittoken->payload.attributes = attributes;
	einittoken->payload.xfrm = xfrm;

	memcpy(&einittoken->cpusvnle, &report.cpusvn,
		   sizeof(report.cpusvn));
	einittoken->isvsvnle = report.isvsvn;
	einittoken->isvprodidle = report.isvprodid;

	einittoken->maskedattributesle = report.attributes;
	einittoken->maskedxfrmle = report.xfrm;
	einittoken->maskedmiscselectle = report.miscselect;

	if (!sign_einittoken(einittoken))
		return false;

	return true;
}

void encl_body(struct sgx_launch_request *req, struct sgx_einittoken *token)
{
	struct sgx_einittoken tmp;
	uint8_t mrenclave[32];
	uint8_t mrsigner[32];
	uint64_t attributes;
	uint64_t xfrm;

	if (!req)
		return;

	memcpy(mrenclave, req->mrenclave, sizeof(mrenclave));
	memcpy(mrsigner, req->mrsigner, sizeof(mrsigner));
	memcpy(&attributes, &req->attributes, sizeof(uint64_t));
	memcpy(&xfrm, &req->xfrm, sizeof(uint64_t));
	memset(&tmp, 0, sizeof(tmp));

	if (!create_einittoken(mrenclave, mrsigner, attributes, xfrm, &tmp))
		return;

	memcpy(token, &tmp, sizeof(*token));
}
