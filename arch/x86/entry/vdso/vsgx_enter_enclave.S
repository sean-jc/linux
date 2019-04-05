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
 *
 * @leaf:	**IN \%eax** - ENCLU leaf, must be EENTER or ERESUME
 * @tcs:	**IN \%rbx** - TCS, must be non-NULL
 * @ex_info:	**IN \%rcx** - Optional 'struct sgx_enclave_exception' pointer
 *
 * Return:
 *  **OUT \%eax** -
 *  %0 on a clean entry/exit to/from the enclave, %-EINVAL if ENCLU leaf is
 *  not allowed or if TCS is NULL, %-EFAULT if ENCLU or the enclave faults
 *
 * **Important!**  __vdso_sgx_enter_enclave() is **NOT** compliant with the
 * x86-64 ABI, i.e. cannot be called from standard C code.   As noted above,
 * input parameters must be passed via ``%eax``, ``%rbx`` and ``%rcx``, with
 * the return value passed via ``%eax``.  All registers except ``%rsp`` must
 * be treated as volatile from the caller's perspective, including but not
 * limited to GPRs, EFLAGS.DF, MXCSR, FCW, etc...  Conversely, the enclave
 * being run **must** preserve the untrusted ``%rsp`` and stack.
 */
__vdso_sgx_enter_enclave(u32 leaf, void *tcs,
			 struct sgx_enclave_exception *ex_info)
{
	if (leaf != SGX_EENTER && leaf != SGX_ERESUME)
		return -EINVAL;

	if (!tcs)
		return -EINVAL;

	try {
		ENCLU[leaf];
	} catch (exception) {
		if (e)
			*e = exception;
		return -EFAULT;
	}

	return 0;
}
#endif
ENTRY(__vdso_sgx_enter_enclave)
	/* EENTER <= leaf <= ERESUME */
	cmp	$0x2, %eax
	jb	bad_input

	cmp	$0x3, %eax
	ja	bad_input

	/* TCS must be non-NULL */
	test	%rbx, %rbx
	je	bad_input

	/* Save @exception_info */
	push	%rcx

	/* Load AEP for ENCLU */
	lea	1f(%rip),  %rcx
1:	enclu

	add	$0x8, %rsp
	xor	%eax, %eax
	ret

bad_input:
	mov     $(-EINVAL), %rax
	ret

.pushsection .fixup, "ax"
	/* Re-load @exception_info and fill it (if it's non-NULL) */
2:	pop	%rcx
	test    %rcx, %rcx
	je      3f

	mov	%eax, EX_LEAF(%rcx)
	mov	%di,  EX_TRAPNR(%rcx)
	mov	%si,  EX_ERROR_CODE(%rcx)
	mov	%rdx, EX_ADDRESS(%rcx)
3:	mov	$(-EFAULT), %rax
	ret
.popsection

_ASM_VDSO_EXTABLE_HANDLE(1b, 2b)

ENDPROC(__vdso_sgx_enter_enclave)
