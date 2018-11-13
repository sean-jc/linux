/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/**
* Copyright(c) 2016-18 Intel Corporation.
*/

	.text

	.global sgx_call
sgx_call:
	push	%rbx
	mov	$0x02, %rax
	mov	%rdx, %rbx
	call	*%r8
	pop	%rbx
	ret
