// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Derived from TinyCrypt CMAC implementation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

#include <asm/sgx.h>
#include "cmac_mode.h"

/* max number of calls until change the key (2^48).*/
const static uint64_t MAX_CALLS = ((uint64_t)1 << 48);

/*
 *  gf_wrap -- In our implementation, GF(2^128) is represented as a 16 byte
 *  array with byte 0 the most significant and byte 15 the least significant.
 *  High bit carry reduction is based on the primitive polynomial
 *
 *                     X^128 + X^7 + X^2 + X + 1,
 *
 *  which leads to the reduction formula X^128 = X^7 + X^2 + X + 1. Indeed,
 *  since 0 = (X^128 + X^7 + X^2 + 1) mod (X^128 + X^7 + X^2 + X + 1) and since
 *  addition of polynomials with coefficients in Z/Z(2) is just XOR, we can
 *  add X^128 to both sides to get
 *
 *       X^128 = (X^7 + X^2 + X + 1) mod (X^128 + X^7 + X^2 + X + 1)
 *
 *  and the coefficients of the polynomial on the right hand side form the
 *  string 1000 0111 = 0x87, which is the value of gf_wrap.
 *
 *  This gets used in the following way. Doubling in GF(2^128) is just a left
 *  shift by 1 bit, except when the most significant bit is 1. In the latter
 *  case, the relation X^128 = X^7 + X^2 + X + 1 says that the high order bit
 *  that overflows beyond 128 bits can be replaced by addition of
 *  X^7 + X^2 + X + 1 <--> 0x87 to the low order 128 bits. Since addition
 *  in GF(2^128) is represented by XOR, we therefore only have to XOR 0x87
 *  into the low order byte after a left shift when the starting high order
 *  bit is 1.
 */
const unsigned char gf_wrap = 0x87;

/*
 *  assumes: out != NULL and points to a GF(2^n) value to receive the
 *            doubled value;
 *           in != NULL and points to a 16 byte GF(2^n) value
 *            to double;
 *           the in and out buffers do not overlap.
 *  effects: doubles the GF(2^n) value pointed to by "in" and places
 *           the result in the GF(2^n) value pointed to by "out."
 */
void gf_double(uint8_t *out, uint8_t *in)
{
	/* start with low order byte */
	uint8_t *x = in + (AES_BLOCK_SIZE - 1);

	/* if msb == 1, we need to add the gf_wrap value, otherwise add 0 */
	uint8_t carry = (in[0] >> 7) ? gf_wrap : 0;

	out += (AES_BLOCK_SIZE - 1);
	for (;;) {
		*out-- = (*x << 1) ^ carry;
		if (x == in)
			break;
		carry = *x-- >> 7;
	}
}

/**
 * tc_cmac_setup - configures the CMAC state to use the given AES key
 *
 * @s: the state to set up
 * @key: the key to use:w
 * @ctx: AES context
 */
void tc_cmac_setup(struct tc_cmac_struct *s, const uint8_t *key,
		   struct crypto_aes_ctx *ctx)
{
	/* put s into a known state */
	tc_cmac_erase(s);
	s->ctx = ctx;

	/* configure the encryption key used by the underlying block cipher */
	aesni_set_key(ctx, key, AES_KEYSIZE_128);

	/* compute s->K1 and s->K2 from s->iv using s->keyid */
	memset(s->iv, 0, AES_BLOCK_SIZE);
	aesni_enc(ctx, s->iv, s->iv);

	gf_double (s->K1, s->iv);
	gf_double (s->K2, s->K1);

	/* reset s->iv to 0 in case someone wants to compute now */
	tc_cmac_init(s);
}

/**
 * tc_cmac_erase - erases the CMAC state
 *
 * @s:	the state to erase
 */
void tc_cmac_erase(struct tc_cmac_struct *s)
{
	memset(s, 0, sizeof(*s));
}

/**
 * tc_cmac_init - initializes a new CMAC computation
 *
 * @s:	the state to initialize
 */
void tc_cmac_init(struct tc_cmac_struct *s)
{
	/* CMAC starts with an all zero initialization vector */
	memset(s->iv, 0, AES_BLOCK_SIZE);

	/* and the leftover buffer is empty */
	memset(s->leftover, 0, AES_BLOCK_SIZE);
	s->leftover_offset = 0;

	/* Set countdown to max number of calls allowed before re-keying: */
	s->countdown = MAX_CALLS;
}

/**
 * tc_cmac_update - incrementally computes CMAC over the next data segment
 *
 * s:		the CMAC state
 * data:	the next data segment to MAC
 * dlen:	the length of data in bytes
 */
void tc_cmac_update(struct tc_cmac_struct *s, const uint8_t *data, size_t dlen)
{
	uint32_t i;

	s->countdown--;

	if (s->leftover_offset > 0) {
		/* last data added to s didn't end on a AES_BLOCK_SIZE byte
		 * boundary
		 */
		size_t remaining_space = AES_BLOCK_SIZE - s->leftover_offset;

		if (dlen < remaining_space) {
			/* still not enough data to encrypt this time either */
			memcpy(&s->leftover[s->leftover_offset], data,
			       dlen);
			s->leftover_offset += dlen;
			return;
		}
		/* leftover block is now full; encrypt it first */
		memcpy(&s->leftover[s->leftover_offset], data, remaining_space);
		dlen -= remaining_space;
		data += remaining_space;
		s->leftover_offset = 0;

		for (i = 0; i < AES_BLOCK_SIZE; ++i)
			s->iv[i] ^= s->leftover[i];

		aesni_enc(s->ctx, s->iv, s->iv);
	}

	/* CBC encrypt each (except the last) of the data blocks */
	while (dlen > AES_BLOCK_SIZE) {
		for (i = 0; i < AES_BLOCK_SIZE; ++i)
			s->iv[i] ^= data[i];
		aesni_enc(s->ctx, s->iv, s->iv);
		data += AES_BLOCK_SIZE;
		dlen  -= AES_BLOCK_SIZE;
	}

	if (dlen > 0) {
		/* save leftover data for next time */
		memcpy(s->leftover, data, dlen);
		s->leftover_offset = dlen;
	}
}

/**
 * tc_cmac_final - generates the tag from the CMAC state
 *
 * @tag:	the CMAC tag
 * @s:		CMAC state
 */
void tc_cmac_final(uint8_t *tag, struct tc_cmac_struct *s)
{
	uint8_t *k;
	uint32_t i;

	if (s->leftover_offset == AES_BLOCK_SIZE) {
		/* the last message block is a full-sized block */
		k = (uint8_t *) s->K1;
	} else {
		/* the final message block is not a full-sized  block */
		size_t remaining = AES_BLOCK_SIZE - s->leftover_offset;

		memset(&s->leftover[s->leftover_offset], 0, remaining);
		s->leftover[s->leftover_offset] = TC_CMAC_PADDING;
		k = (uint8_t *) s->K2;
	}
	for (i = 0; i < AES_BLOCK_SIZE; ++i)
		s->iv[i] ^= s->leftover[i] ^ k[i];

	aesni_enc(s->ctx, tag, s->iv);

	/* erasing state: */
	tc_cmac_erase(s);
}
