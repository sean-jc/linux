/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/linkage.h>
#include <asm/export.h>
#include <asm/errno.h>

#include "extable.h"

#define EX_LEAF		0*8
#define EX_TRAPNR	0*8+4
#define EX_ERROR_CODE	0*8+6
#define EX_ADDRESS	1*8

.code64
.section .text, "ax"

#ifdef SGX_KERNEL_DOC
/**
 * __vdso_sgx_enter_enclave() - Enter an SGX enclave
 * @leaf:	ENCLU leaf, must be EENTER or ERESUME
 * @tcs:	TCS, must be non-NULL
 * @ex_info:	Optional struct sgx_enclave_exception instance
 * @callback:	Optional callback function to be called on enclave exit or
 *		exception
 *
 * **Important!**  __vdso_sgx_enter_enclave() is **NOT** compliant with the
 * x86-64 ABI, i.e. cannot be called from standard C code. As noted above,
 * input parameters must be passed via ``%eax``, ``8(%rsp)``, ``0x10(%rsp)`` and
 * ``0x18(%rsp)``, with the return value passed via ``%eax``. All other
 * registers will be passed through to the enclave as is. All registers except
 * ``%rbp`` must be treated as volatile from the caller's perspective, including
 * but not limited to GPRs, EFLAGS.DF, MXCSR, FCW, etc... Conversely, the
 * enclave being run **must** preserve the untrusted ``%rbp``.
 *
 * ``callback`` has the following signature:
 * int callback(long rdi, long rsi, long rdx,
 *		struct sgx_enclave_exinfo *exinfo, long r8, long r9,
 *		void *tcs, long ursp);
 * ``callback`` **shall** follow x86_64 ABI. All GPRs **except** ``%rax``,
 * ``%rbx`` and ``rcx`` are passed through to ``callback``. ``%rdi``, ``%rsi``,
 * ``%rdx``, ``%r8``, ``%r9``, along with the value of ``%rsp`` when the enclave
 * exited/excepted, can be accessed directly as input parameters, while other
 * GPRs can be accessed in assembly if needed.  A positive value returned from
 * ``callback`` will be treated as an ENCLU leaf (e.g. EENTER/ERESUME) to
 * reenter the enclave (without popping the extra data pushed by the enclave off
 * the stack), while 0 (zero) or a negative return value will be passed back to
 * the caller of __vdso_sgx_enter_enclave(). It is also safe to leave
 * ``callback`` via ``longjmp()`` or by throwing a C++ exception.
 *
 * Return:
 *    0 on success,
 *    -EINVAL if ENCLU leaf is not allowed,
 *    -EFAULT if ENCL or the enclave faults or non-positive value is returned
 *     from the callback.
 */
typedef int (*sgx_callback)(long rdi, long rsi, long rdx,
			    struct sgx_enclave_exinfo *exinfo, long r8,
			    long r9, void *tcs, long ursp);
int __vdso_sgx_enter_enclave(int leaf, void *tcs,
			     struct sgx_enclave_exinfo *exinfo,
			     sgx_callback callback)
{
	while (leaf == EENTER || leaf == ERESUME) {
		int rc;
		try {
			ENCLU[leaf];
			rc = 0;
			if (exinfo)
				exinfo->leaf = EEXIT;
		} catch (exception) {
			rc = -EFAULT;
			if (exinfo)
				*exinfo = exception;
		}

		leaf = callback ? (*callback)(
			rdi, rsi, rdx, exinfo, r8, r9, tcs, ursp) : rc;
	}

	if (leaf > 0)
		return -EINVAL;

	return leaf;
}
#endif
ENTRY(__vdso_sgx_enter_enclave)
	/* Prolog */
	.cfi_startproc
	push	%rbp
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%rbp, 0
	mov	%rsp, %rbp
	.cfi_def_cfa_register	%rbp

1:	/* EENTER <= leaf <= ERESUME */
	cmp	$0x2, %eax
	jb	6f
	cmp	$0x3, %eax
	ja	6f

	/* Load TCS and AEP */
	mov	0x10(%rbp), %rbx
	lea	2f(%rip), %rcx

	/* Single ENCLU serving as both EENTER and AEP (ERESUME) */
2:	enclu

	/* EEXIT path */
	xor	%ebx, %ebx
3:	mov	0x18(%rbp), %rcx
	jrcxz	4f
	mov	%eax, EX_LEAF(%rcx)
	jnc	4f
	mov	%di, EX_TRAPNR(%rcx)
	mov	%si, EX_ERROR_CODE(%rcx)
	mov	%rdx, EX_ADDRESS(%rcx)

4:	/* Call *callback if supplied */
	mov	0x20(%rbp), %rax
	test	%rax, %rax
	/* At this point, %ebx holds the effective return value, which shall be
	 * returned if no callback is specified */
	cmovz	%rbx, %rax
	jz	7f
	/* Align stack per x86_64 ABI. The original %rsp is saved in %rbx to be
	 * restored after *callback returns. */
	mov	%rsp, %rbx
	and	$-0x10, %rsp
	/* Clear RFLAGS.DF per x86_64 ABI */
	cld
	/* Parameters for *callback */
	push	%rbx
	push	0x10(%rbp)
	/* Call *%rax via retpoline */
	call	40f
	/* Restore %rsp to its original value left off by the enclave from last
	 * exit */
	mov	%rbx, %rsp
	/* Positive return value from *callback will be interpreted as an ENCLU
	 * leaf, while a non-positive value will be interpreted as the return
	 * value to be passed back to the caller. */
	jmp	1b
40:	/* retpoline */
	call	42f
41:	pause
	lfence
	jmp	41b
42:	mov	%rax, (%rsp)
	ret

5:	/* Exception path */
	mov	$-EFAULT, %ebx
	stc
	jmp	3b

6:	/* Unsupported ENCLU leaf */
	cmp	$0, %eax
	jle	7f
	mov	$-EINVAL, %eax

7:	/* Epilog */
	leave
	.cfi_def_cfa		%rsp, 8
	ret
	.cfi_endproc

_ASM_VDSO_EXTABLE_HANDLE(2b, 5b)

ENDPROC(__vdso_sgx_enter_enclave)
