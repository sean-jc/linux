/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/linkage.h>
#include <asm/export.h>
#include <asm/errno.h>
#include <asm/enclu.h>

#include "extable.h"

/* Offset of 'struct sgx_enclave_run' relative to %rbp. */
#define SGX_ENCLAVE_RUN_PTR	2*8

/* Offsets into 'struct sgx_enclave_run'. */
#define SGX_ENCLAVE_RUN_TSC		0*8
#define SGX_ENCLAVE_RUN_FLAGS		1*8
#define SGX_ENCLAVE_RUN_EXIT_REASON	1*8 + 4
#define SGX_ENCLAVE_RUN_USER_HANDLER	2*8
/* #define SGX_ENCLAVE_RUN_USER_DATA	3*8 */
#define SGX_ENCLAVE_RUN_EXCEPTION	4*8

#define SGX_SYNCHRONOUS_EXIT		0
#define SGX_EXCEPTION_EXIT		1

/* Offsets into sgx_enter_enclave.exception. */
#define SGX_EX_LEAF			0*8
#define SGX_EX_TRAPNR			0*8+4
#define SGX_EX_ERROR_CODE		0*8+6
#define SGX_EX_ADDRESS			1*8

.code64
.section .text, "ax"

SYM_FUNC_START(__vdso_sgx_enter_enclave)
	/* Prolog */
	.cfi_startproc
	push	%rbp
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%rbp, 0
	mov	%rsp, %rbp
	.cfi_def_cfa_register	%rbp
	push	%rbx
	.cfi_rel_offset		%rbx, -8

	mov	%ecx, %eax
.Lenter_enclave:
	/* EENTER <= leaf <= ERESUME */
	cmp	$EENTER, %eax
	jb	.Linvalid_input
	cmp	$ERESUME, %eax
	ja	.Linvalid_input

	mov	SGX_ENCLAVE_RUN_PTR(%rbp), %rcx

	/* No flags are currently defined/supported. */
	cmpl	$0, SGX_ENCLAVE_RUN_FLAGS(%rcx)
	jne	.Linvalid_input

	/* Load TCS and AEP */
	mov	SGX_ENCLAVE_RUN_TSC(%rcx), %rbx
	lea	.Lasync_exit_pointer(%rip), %rcx

	/* Single ENCLU serving as both EENTER and AEP (ERESUME) */
.Lasync_exit_pointer:
.Lenclu_eenter_eresume:
	enclu

	/* EEXIT jumps here unless the enclave is doing something fancy. */
	mov	SGX_ENCLAVE_RUN_PTR(%rbp), %rbx

	/* Set exit_reason. */
	movl	$SGX_SYNCHRONOUS_EXIT, SGX_ENCLAVE_RUN_EXIT_REASON(%rbx)

	/* Invoke userspace's exit handler if one was provided. */
.Lhandle_exit:
	cmpq	$0, SGX_ENCLAVE_RUN_USER_HANDLER(%rbx)
	jne	.Linvoke_userspace_handler

	/* Success, in the sense that ENCLU was attempted. */
	xor	%eax, %eax

.Lout:
	pop	%rbx
	leave
	.cfi_def_cfa		%rsp, 8
	ret

	/* The out-of-line code runs with the pre-leave stack frame. */
	.cfi_def_cfa		%rbp, 16

.Linvalid_input:
	mov	$(-EINVAL), %eax
	jmp	.Lout

.Lhandle_exception:
	mov	SGX_ENCLAVE_RUN_PTR(%rbp), %rbx

	/* Set the exit_reason and exception info. */
	movl	$SGX_EXCEPTION_EXIT, SGX_ENCLAVE_RUN_EXIT_REASON(%rbx)

	mov	%eax, (SGX_ENCLAVE_RUN_EXCEPTION + SGX_EX_LEAF)(%rbx)
	mov	%di,  (SGX_ENCLAVE_RUN_EXCEPTION + SGX_EX_TRAPNR)(%rbx)
	mov	%si,  (SGX_ENCLAVE_RUN_EXCEPTION + SGX_EX_ERROR_CODE)(%rbx)
	mov	%rdx, (SGX_ENCLAVE_RUN_EXCEPTION + SGX_EX_ADDRESS)(%rbx)
	jmp	.Lhandle_exit

.Linvoke_userspace_handler:
	/* Pass the untrusted RSP (at exit) to the callback via %rcx. */
	mov	%rsp, %rcx

	/* Save @e, %rbx is about to be clobbered. */
	mov	%rbx, %rax

	/* Save the untrusted RSP offset in %rbx (non-volatile register). */
	mov	%rsp, %rbx
	and	$0xf, %rbx

	/*
	 * Align stack per x86_64 ABI. Note, %rsp needs to be 16-byte aligned
	 * _after_ pushing the parameters on the stack, hence the bonus push.
	 */
	and	$-0x10, %rsp
	push	%rax

	/* Push @e as a param to the callback. */
	push	%rax

	/* Clear RFLAGS.DF per x86_64 ABI */
	cld

	/* Load the callback pointer to %rax and invoke it via retpoline. */
	mov	SGX_ENCLAVE_RUN_USER_HANDLER(%rax), %rax
	call	.Lretpoline

	/* Undo the post-exit %rsp adjustment. */
	lea	0x10(%rsp, %rbx), %rsp

	/*
	 * If the return from callback is zero or negative, return immediately,
	 * else re-execute ENCLU with the postive return value interpreted as
	 * the requested ENCLU leaf.
	 */
	cmp	$0, %eax
	jle	.Lout
	jmp	.Lenter_enclave

.Lretpoline:
	call	2f
1:	pause
	lfence
	jmp	1b
2:	mov	%rax, (%rsp)
	ret
	.cfi_endproc

_ASM_VDSO_EXTABLE_HANDLE(.Lenclu_eenter_eresume, .Lhandle_exception)

SYM_FUNC_END(__vdso_sgx_enter_enclave)
