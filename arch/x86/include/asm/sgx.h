// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
// Suresh Siddha <suresh.b.siddha@intel.com>
// Sean Christopherson <sean.j.christopherson@intel.com>

#ifndef _ASM_X86_SGX_H
#define _ASM_X86_SGX_H

#include <asm/sgx_arch.h>
#include <asm/asm.h>
#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/rwsem.h>
#include <linux/types.h>

#define SGX_CPUID 0x12

enum sgx_cpuid {
	SGX_CPUID_CAPABILITIES	= 0,
	SGX_CPUID_ATTRIBUTES	= 1,
	SGX_CPUID_EPC_BANKS	= 2,
};

enum sgx_commands {
	ECREATE	= 0x0,
	EADD	= 0x1,
	EINIT	= 0x2,
	EREMOVE	= 0x3,
	EDGBRD	= 0x4,
	EDGBWR	= 0x5,
	EEXTEND	= 0x6,
	ELDU	= 0x8,
	EBLOCK	= 0x9,
	EPA	= 0xA,
	EWB	= 0xB,
	ETRACK	= 0xC,
	EAUG	= 0xD,
	EMODPR	= 0xE,
	EMODT	= 0xF,
};

#define IS_ENCLS_FAULT(r) ((r) & 0xffff0000)

#define __encls_ret_N(rax, inputs...)			\
	({						\
	int ret;					\
	asm volatile(					\
	"1: .byte 0x0f, 0x01, 0xcf;\n\t"		\
	"2:\n"						\
	".section .fixup,\"ax\"\n"			\
	"3: shll $16,%%eax\n"				\
	"   jmp 2b\n"					\
	".previous\n"					\
	_ASM_EXTABLE_FAULT(1b, 3b)			\
	: "=a"(ret)					\
	: "a"(rax), inputs				\
	: "memory");					\
	ret;						\
	})

#define __encls_ret_1(rax, rcx)				\
	({						\
	__encls_ret_N(rax, "c"(rcx));			\
	})

#define __encls_ret_2(rax, rbx, rcx)			\
	({						\
	__encls_ret_N(rax, "b"(rbx), "c"(rcx));		\
	})

#define __encls_ret_3(rax, rbx, rcx, rdx)			\
	({							\
	__encls_ret_N(rax, "b"(rbx), "c"(rcx), "d"(rdx));	\
	})

#define __encls_N(rax, rbx_out, inputs...)		\
	({						\
	int ret;					\
	asm volatile(					\
	"1: .byte 0x0f, 0x01, 0xcf;\n\t"		\
	"   xor %%eax,%%eax;\n"				\
	"2:\n"						\
	".section .fixup,\"ax\"\n"			\
	"3: shll $16,%%eax\n"				\
	"   jmp 2b\n"					\
	".previous\n"					\
	_ASM_EXTABLE_FAULT(1b, 3b)				\
	: "=a"(ret), "=b"(rbx_out)			\
	: "a"(rax), inputs				\
	: "memory");					\
	ret;						\
	})

#define __encls_2(rax, rbx, rcx)				\
	({							\
	unsigned long ign_rbx_out;				\
	__encls_N(rax, ign_rbx_out, "b"(rbx), "c"(rcx));	\
	})

#define __encls_1_1(rax, data, rcx)			\
	({						\
	unsigned long rbx_out;				\
	int ret = __encls_N(rax, rbx_out, "c"(rcx));	\
	if (!ret)					\
		data = rbx_out;				\
	ret;						\
	})

static inline int __ecreate(struct sgx_pageinfo *pginfo, void *secs)
{
	return __encls_2(ECREATE, pginfo, secs);
}

static inline int __eextend(void *secs, void *epc)
{
	return __encls_2(EEXTEND, secs, epc);
}

static inline int __eadd(struct sgx_pageinfo *pginfo, void *epc)
{
	return __encls_2(EADD, pginfo, epc);
}

static inline int __einit(void *sigstruct, struct sgx_einittoken *einittoken,
			  void *secs)
{
	return __encls_ret_3(EINIT, sigstruct, secs, einittoken);
}

static inline int __eremove(void *epc)
{
	return __encls_ret_1(EREMOVE, epc);
}

static inline int __edbgwr(unsigned long addr, unsigned long *data)
{
	return __encls_2(EDGBWR, *data, addr);
}

static inline int __edbgrd(unsigned long addr, unsigned long *data)
{
	return __encls_1_1(EDGBRD, *data, addr);
}

static inline int __etrack(void *epc)
{
	return __encls_ret_1(ETRACK, epc);
}

static inline int __eldu(struct sgx_pageinfo *pginfo, void *epc, void *va)
{
	return __encls_ret_3(ELDU, pginfo, epc, va);
}

static inline int __eblock(void *epc)
{
	return __encls_ret_1(EBLOCK, epc);
}

static inline int __epa(void *epc)
{
	unsigned long rbx = SGX_PAGE_TYPE_VA;

	return __encls_2(EPA, rbx, epc);
}

static inline int __ewb(struct sgx_pageinfo *pginfo, void *epc, void *va)
{
	return __encls_ret_3(EWB, pginfo, epc, va);
}

static inline int __eaug(struct sgx_pageinfo *pginfo, void *epc)
{
	return __encls_2(EAUG, pginfo, epc);
}

static inline int __emodpr(struct sgx_secinfo *secinfo, void *epc)
{
	return __encls_ret_2(EMODPR, secinfo, epc);
}

static inline int __emodt(struct sgx_secinfo *secinfo, void *epc)
{
	return __encls_ret_2(EMODT, secinfo, epc);
}

extern bool sgx_enabled;

#endif /* _ASM_X86_SGX_H */
