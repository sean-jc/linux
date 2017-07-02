// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

#include <linux/types.h>

/* This might look a bit ugly but is needed because of the way asm/string_64.h
 * redefines the symbols depending on the CONFIG_KASAN flag.
 */
#ifdef CONFIG_KASAN
void *__memset(void *s, int c, size_t n)
#else
void *memset(void *s, int c, size_t n)
#endif
{
	unsigned long i;

	for (i = 0; i < n; i++)
		((unsigned char *)s)[i] = c;

	return s;
}

#ifdef CONFIG_KASAN
void *__memcpy(void *dest, const void *src, size_t n)
#else
void *memcpy(void *dest, const void *src, size_t n)
#endif
{
	size_t i;

	for (i = 0; i < n; i++)
		((char *)dest)[i] = ((char *)src)[i];

	return dest;
}
