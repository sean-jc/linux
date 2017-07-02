// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Derived from TinyCrypt CMAC implementation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

#ifndef CMAC_MODE_H
#define CMAC_MODE_H

#include <stddef.h>
#include <crypto/aes.h>

/* padding for last message block */
#define TC_CMAC_PADDING 0x80

/* struct tc_cmac_struct represents the state of a CMAC computation */
struct tc_cmac_struct {
	/* initialization vector */
	uint8_t iv[AES_BLOCK_SIZE];
	/* used if message length is a multiple of block_size bytes */
	uint8_t K1[AES_BLOCK_SIZE];
	/* used if message length isn't a multiple block_size bytes */
	uint8_t K2[AES_BLOCK_SIZE];
	/* where to put bytes that didn't fill a block */
	uint8_t leftover[AES_BLOCK_SIZE];
	/* identifies the encryption key */
	uint32_t keyid;
	/* next available leftover location */
	uint32_t leftover_offset;
	/* AES key schedule */
	struct crypto_aes_ctx *ctx;
	/* calls to tc_cmac_update left before re-key */
	uint64_t countdown;
};

void tc_cmac_setup(struct tc_cmac_struct *s, const uint8_t *key,
		   struct crypto_aes_ctx *ctx);

void tc_cmac_erase(struct tc_cmac_struct *s);

void tc_cmac_init(struct tc_cmac_struct *s);

void tc_cmac_update(struct tc_cmac_struct *s, const uint8_t *data, size_t dlen);

void tc_cmac_final(uint8_t *tag, struct tc_cmac_struct *s);

asmlinkage int aesni_set_key(struct crypto_aes_ctx *ctx, const u8 *in_key,
			     unsigned int key_len);
asmlinkage void aesni_enc(struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);

#endif /* CMAC_MODE_H */
