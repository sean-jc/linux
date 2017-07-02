// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

#include <asm/sgx_le.h>
#include <sgx_asm.h>

	.text

	.global sgx_get_token
sgx_get_token:
	push	%rbx
	mov	$0x02, %rax
	mov	%rsi, %rbx
	mov	%rdx, %rsi
	mov	$sgx_async_exit, %rcx
sgx_async_exit:
	ENCLU
	pop	%rbx
	ret

	.global sgx_sys_read
sgx_sys_read:
	mov	$0, %rax
	mov	%rsi, %rdx /* buf */
	mov	%rdi, %rsi /* count */
	mov	$SGX_LE_PIPE_FD, %rdi
	syscall
	ret

	.global sgx_sys_write
sgx_sys_write:
	mov	$1, %rax
	mov	%rsi, %rdx /* buf */
	mov	%rdi, %rsi /* count */
	mov	$SGX_LE_PIPE_FD, %rdi
	syscall
	ret

	.global sgx_sys_close
sgx_sys_close:
	mov	$3, %rax
	syscall
	ret

	.global sgx_sys_mmap
sgx_sys_mmap:
	mov	$9, %rax
	mov	%rdi, %r8 /* fd */
	xor	%rdi, %rdi /* any address */

	mov	$0x07, %rdx /* rwx */
	mov	$0x01, %r10 /* shared */
	mov	$0x00, %r9 /* offset */
	syscall
	ret

	.global sgx_sys_ioctl
sgx_sys_ioctl:
	mov	$16, %rax
	syscall
	ret

	.global sgx_sys_exit
sgx_sys_exit:
	mov	$60, %rax
	syscall
