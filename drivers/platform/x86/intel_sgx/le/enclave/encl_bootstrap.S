// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
// Haim Cohen <haim.cohen@intel.com>
// Sean Christopherson <sean.j.christopherson@intel.com>

#include <sgx_asm.h>

	.section ".tcs", "a"
	.balign	4096

	.fill	1, 8, 0			# STATE (set by CPU)
	.fill	1, 8, 0			# FLAGS
	.long	encl_ssa		# OSSA
	.fill	1, 4, 0
	.fill	1, 4, 0			# CSSA (set by CPU)
	.fill	1, 4, 1			# NSSA
	.long	encl_entry		# OENTRY
	.fill	1, 4, 0
	.fill	1, 8, 0			# AEP (set by EENTER and ERESUME)
	.fill	1, 8, 0			# OFSBASE
	.fill	1, 8, 0			# OGSBASE
	.fill	1, 4, 0xFFFFFFFF 	# FSLIMIT
	.fill	1, 4, 0xFFFFFFFF	# GSLIMIT
	.fill	503, 8, 0		# Reserved

	.text

encl_entry:
	# %rbx contains the base address for TCS, which is also the first
	# address inside the enclave. By adding $le_stack_end to it, we get the
	# absolute address for the stack.
	lea	(encl_stack)(%rbx), %rax
	xchg	%rsp, %rax
	push	%rax

	push	%rcx # push the address after EENTER
	push	%rbx # push the enclave base address

	call	encl_body

	pop	%rbx # pop the enclave base address

	# Restore XSAVE registers to a synthetic state.
	mov     $0xFFFFFFFF, %rax
	mov     $0xFFFFFFFF, %rdx
	lea	(xsave_area)(%rbx), %rdi
	fxrstor	(%rdi)

	# Clear GPRs
	xor     %rcx, %rcx
	xor     %rdx, %rdx
	xor     %rdi, %rdi
	xor     %rsi, %rsi
	xor     %r8, %r8
	xor     %r9, %r9
	xor     %r10, %r10
	xor     %r11, %r11
	xor     %r12, %r12
	xor     %r13, %r13
	xor     %r14, %r14
	xor     %r15, %r15

	# Reset status flags
	add     %rdx, %rdx # OF = SF = AF = CF = 0; ZF = PF = 1

	pop	%rbx # pop the address after EENTER

	# Restore the caller stack.
	pop	%rax
	mov	%rax, %rsp

	# EEXIT
	mov	$4, %rax
	enclu

	.global sgx_ereport
sgx_ereport:
	push	%rbx
	xor	%rax, %rax /* EREPORT */
	mov	%rdi, %rbx  /* TARGETINFO */
	mov	%rsi, %rcx /* REPORTDATA */
	ENCLU
	pop	%rbx
	ret

	.global sgx_egetkey
sgx_egetkey:
	push	%rbx
	mov	$0x01, %rax /* EGETKEY */
	mov	%rdi, %rbx /* KEYREQUEST */
	mov	%rsi, %rcx  /* KEY */
	ENCLU
	pop	%rbx
	ret

	.section ".data", "aw"

encl_ssa:
	.space 4096

xsave_area:
	.fill	1, 4, 0x037F		# FCW
	.fill	5, 4, 0
	.fill	1, 4, 0x1F80		# MXCSR
	.fill	1, 4, 0xFFFF		# MXCSR_MASK
	.fill	123, 4, 0
	.fill	1, 4, 0x80000000	# XCOMP_BV[63] = 1, compaction mode
	.fill	12, 4, 0

	.balign 4096
	.space 8192
encl_stack:
