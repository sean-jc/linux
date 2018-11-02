/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/**
 * Copyright(c) 2016-18 Intel Corporation.
 *
 * Contains data structures defined by the SGX architecture.  Data structures
 * defined by the Linux software stack should not be placed here.
 */
#ifndef _ASM_X86_SGX_ARCH_H
#define _ASM_X86_SGX_ARCH_H

/**
 * enum sgx_encls_leaves - ENCLS leaf functions
 * %SGX_ECREATE:	Create an enclave.
 * %SGX_EADD:		Add a page to an uninitialized enclave.
 * %SGX_EINIT:		Initialize an enclave, i.e. launch an enclave.
 * %SGX_EREMOVE:	Remove a page from an enclave.
 * %SGX_EDBGRD:		Read a word from an enclve (peek).
 * %SGX_EDBGWR:		Write a word to an enclave (poke).
 * %SGX_EEXTEND:	Measure 256 bytes of an added enclave page.
 * %SGX_ELDB:		Load a swapped page in blocked state.
 * %SGX_ELDU:		Load a swapped page in unblocked state.
 * %SGX_EBLOCK:		Change page state to blocked i.e. entering hardware
 *			threads cannot access it and create new TLB entries.
 * %SGX_EPA:		Create a Version Array (VA) page used to store isvsvn
 *			number for a swapped EPC page.
 * %SGX_EWB:		Swap an enclave page to the regular memory. Checks that
 *			all threads have exited that were in the previous
 *			shoot-down sequence.
 * %SGX_ETRACK:		Start a new shoot down sequence. Used to together with
 *			EBLOCK to make sure that a page is safe to swap.
 * %SGX_EAUG:		Add a page to an initialized enclave.
 * %SGX_EMODPR:		Restrict an EPC page's permissions.
 * %SGX_EMODT:		Modify the page type of an EPC page.
 */
enum sgx_encls_leaves {
	SGX_ECREATE	= 0x00,
	SGX_EADD	= 0x01,
	SGX_EINIT	= 0x02,
	SGX_EREMOVE	= 0x03,
	SGX_EDGBRD	= 0x04,
	SGX_EDGBWR	= 0x05,
	SGX_EEXTEND	= 0x06,
	SGX_ELDB	= 0x07,
	SGX_ELDU	= 0x08,
	SGX_EBLOCK	= 0x09,
	SGX_EPA		= 0x0A,
	SGX_EWB		= 0x0B,
	SGX_ETRACK	= 0x0C,
	SGX_EAUG	= 0x0D,
	SGX_EMODPR	= 0x0E,
	SGX_EMODT	= 0x0F,
};

#endif /* _ASM_X86_SGX_ARCH_H */
