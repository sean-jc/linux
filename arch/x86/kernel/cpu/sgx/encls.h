/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
#ifndef _X86_ENCLS_H
#define _X86_ENCLS_H

#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/rwsem.h>
#include <linux/types.h>
#include <asm/asm.h>
#include "arch.h"

/**
 * ENCLS_FAULT_FLAG - flag signifying an ENCLS return code is a trapnr
 *
 * ENCLS has its own (positive value) error codes and also generates
 * ENCLS specific #GP and #PF faults.  And the ENCLS values get munged
 * with system error codes as everything percolates back up the stack.
 * Unfortunately (for us), we need to precisely identify each unique
 * error code, e.g. the action taken if EWB fails varies based on the
 * type of fault and on the exact SGX error code, i.e. we can't simply
 * convert all faults to -EFAULT.
 *
 * To make all three error types coexist, we set bit 30 to identify an
 * ENCLS fault.  Bit 31 (technically bits N:31) is used to differentiate
 * between positive (faults and SGX error codes) and negative (system
 * error codes) values.
 */
#define ENCLS_FAULT_FLAG 0x40000000

/**
 * Retrieve the encoded trapnr from the specified return code.
 */
#define ENCLS_TRAPNR(r) ((r) & ~ENCLS_FAULT_FLAG)

/* Issue a WARN() about an ENCLS leaf. */
#define ENCLS_WARN(r, name) {						\
	do {								\
		int _r = (r);						\
		WARN(_r, "sgx: %s returned %d (0x%x)\n", (name), _r,	\
		     _r);						\
	} while (0);							\
}

/**
 * encls_faulted() - Check if ENCLS leaf function faulted
 * @ret:	the return value of an ENCLS leaf function call
 *
 * Return: true if the fault flag is set
 */
static inline bool encls_faulted(int ret)
{
	return (ret & ENCLS_FAULT_FLAG) != 0;
}

/**
 * encls_returned_code() - Check if an ENCLS leaf function returned a code
 * @ret:	the return value of an ENCLS leaf function call
 *
 * Check if an ENCLS leaf function returned an error or information code.
 *
 * Return: true if there was a fault other than an EPCM conflict
 */
static inline bool encls_returned_code(int ret)
{
	return !encls_faulted(ret) && ret;
}

bool encls_failed(int ret);

/**
 * __encls_ret_N - encode an ENCLS leaf that returns an error code in EAX
 * @rax:	leaf number
 * @inputs:	asm inputs for the leaf
 *
 * Emit assembly for an ENCLS leaf that returns an error code, e.g. EREMOVE.
 * And because SGX isn't complex enough as it is, leafs that return an error
 * code also modify flags.
 *
 * Return:
 *	0 on success,
 *	SGX error code on failure
 */
#define __encls_ret_N(rax, inputs...)				\
	({							\
	int ret;						\
	asm volatile(						\
	"1: .byte 0x0f, 0x01, 0xcf;\n\t"			\
	"2:\n"							\
	".section .fixup,\"ax\"\n"				\
	"3: orl $"__stringify(ENCLS_FAULT_FLAG)",%%eax\n"	\
	"   jmp 2b\n"						\
	".previous\n"						\
	_ASM_EXTABLE_FAULT(1b, 3b)				\
	: "=a"(ret)						\
	: "a"(rax), inputs					\
	: "memory", "cc");					\
	ret;							\
	})

#define __encls_ret_1(rax, rcx)		\
	({				\
	__encls_ret_N(rax, "c"(rcx));	\
	})

#define __encls_ret_2(rax, rbx, rcx)		\
	({					\
	__encls_ret_N(rax, "b"(rbx), "c"(rcx));	\
	})

#define __encls_ret_3(rax, rbx, rcx, rdx)			\
	({							\
	__encls_ret_N(rax, "b"(rbx), "c"(rcx), "d"(rdx));	\
	})

/**
 * __encls_N - encode an ENCLS leaf that doesn't return an error code
 * @rax:	leaf number
 * @rbx_out:	optional output variable
 * @inputs:	asm inputs for the leaf
 *
 * Emit assembly for an ENCLS leaf that does not return an error code,
 * e.g. ECREATE.  Leaves without error codes either succeed or fault.
 * @rbx_out is an optional parameter for use by EDGBRD, which returns
 * the the requested value in RBX.
 *
 * Return:
 *   0 on success,
 *   trapnr with ENCLS_FAULT_FLAG set on fault
 */
#define __encls_N(rax, rbx_out, inputs...)			\
	({							\
	int ret;						\
	asm volatile(						\
	"1: .byte 0x0f, 0x01, 0xcf;\n\t"			\
	"   xor %%eax,%%eax;\n"					\
	"2:\n"							\
	".section .fixup,\"ax\"\n"				\
	"3: orl $"__stringify(ENCLS_FAULT_FLAG)",%%eax\n"	\
	"   jmp 2b\n"						\
	".previous\n"						\
	_ASM_EXTABLE_FAULT(1b, 3b)				\
	: "=a"(ret), "=b"(rbx_out)				\
	: "a"(rax), inputs					\
	: "memory");						\
	ret;							\
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
	return __encls_2(SGX_ECREATE, pginfo, secs);
}

static inline int __eextend(void *secs, void *addr)
{
	return __encls_2(SGX_EEXTEND, secs, addr);
}

static inline int __eadd(struct sgx_pageinfo *pginfo, void *addr)
{
	return __encls_2(SGX_EADD, pginfo, addr);
}

static inline int __einit(void *sigstruct, struct sgx_einittoken *einittoken,
			  void *secs)
{
	return __encls_ret_3(SGX_EINIT, sigstruct, secs, einittoken);
}

static inline int __eremove(void *addr)
{
	return __encls_ret_1(SGX_EREMOVE, addr);
}

static inline int __edbgwr(void *addr, unsigned long *data)
{
	return __encls_2(SGX_EDGBWR, *data, addr);
}

static inline int __edbgrd(void *addr, unsigned long *data)
{
	return __encls_1_1(SGX_EDGBRD, *data, addr);
}

static inline int __etrack(void *addr)
{
	return __encls_ret_1(SGX_ETRACK, addr);
}

static inline int __eldu(struct sgx_pageinfo *pginfo, void *addr,
			 void *va)
{
	return __encls_ret_3(SGX_ELDU, pginfo, addr, va);
}

static inline int __eblock(void *addr)
{
	return __encls_ret_1(SGX_EBLOCK, addr);
}

static inline int __epa(void *addr)
{
	unsigned long rbx = SGX_PAGE_TYPE_VA;

	return __encls_2(SGX_EPA, rbx, addr);
}

static inline int __ewb(struct sgx_pageinfo *pginfo, void *addr,
			void *va)
{
	return __encls_ret_3(SGX_EWB, pginfo, addr, va);
}

static inline int __eaug(struct sgx_pageinfo *pginfo, void *addr)
{
	return __encls_2(SGX_EAUG, pginfo, addr);
}

static inline int __emodpr(struct sgx_secinfo *secinfo, void *addr)
{
	return __encls_ret_2(SGX_EMODPR, secinfo, addr);
}

static inline int __emodt(struct sgx_secinfo *secinfo, void *addr)
{
	return __encls_ret_2(SGX_EMODT, secinfo, addr);
}

#endif /* _X86_ENCLS_H */
