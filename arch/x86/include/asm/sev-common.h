/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD SEV header common between the guest and the hypervisor.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#ifndef __ASM_X86_SEV_COMMON_H
#define __ASM_X86_SEV_COMMON_H

#define GHCB_MSR_INFO_POS		0
#define GHCB_DATA_LOW			12
#define GHCB_MSR_INFO_MASK		(BIT_ULL(GHCB_DATA_LOW) - 1)

#define GHCB_DATA(v)			\
	(((unsigned long)(v) & ~GHCB_MSR_INFO_MASK) >> GHCB_DATA_LOW)

/* SEV Information Request/Response */
#define GHCB_MSR_SEV_INFO_RESP		0x001
#define GHCB_MSR_SEV_INFO_REQ		0x002
#define GHCB_MSR_VER_MAX_POS		48
#define GHCB_MSR_VER_MAX_MASK		0xffff
#define GHCB_MSR_VER_MIN_POS		32
#define GHCB_MSR_VER_MIN_MASK		0xffff
#define GHCB_MSR_CBIT_POS		24
#define GHCB_MSR_CBIT_MASK		0xff
#define GHCB_MSR_SEV_INFO(_max, _min, _cbit)				\
	((((_max) & GHCB_MSR_VER_MAX_MASK) << GHCB_MSR_VER_MAX_POS) |	\
	 (((_min) & GHCB_MSR_VER_MIN_MASK) << GHCB_MSR_VER_MIN_POS) |	\
	 (((_cbit) & GHCB_MSR_CBIT_MASK) << GHCB_MSR_CBIT_POS) |	\
	 GHCB_MSR_SEV_INFO_RESP)
#define GHCB_MSR_INFO(v)		((v) & 0xfffUL)
#define GHCB_MSR_PROTO_MAX(v)		(((v) >> GHCB_MSR_VER_MAX_POS) & GHCB_MSR_VER_MAX_MASK)
#define GHCB_MSR_PROTO_MIN(v)		(((v) >> GHCB_MSR_VER_MIN_POS) & GHCB_MSR_VER_MIN_MASK)

/* CPUID Request/Response */
#define GHCB_MSR_CPUID_REQ		0x004
#define GHCB_MSR_CPUID_RESP		0x005
#define GHCB_MSR_CPUID_FUNC_POS		32
#define GHCB_MSR_CPUID_FUNC_MASK	0xffffffff
#define GHCB_MSR_CPUID_VALUE_POS	32
#define GHCB_MSR_CPUID_VALUE_MASK	0xffffffff
#define GHCB_MSR_CPUID_REG_POS		30
#define GHCB_MSR_CPUID_REG_MASK		0x3
#define GHCB_CPUID_REQ_EAX		0
#define GHCB_CPUID_REQ_EBX		1
#define GHCB_CPUID_REQ_ECX		2
#define GHCB_CPUID_REQ_EDX		3
#define GHCB_CPUID_REQ(fn, reg)		\
		(GHCB_MSR_CPUID_REQ | \
		(((unsigned long)reg & GHCB_MSR_CPUID_REG_MASK) << GHCB_MSR_CPUID_REG_POS) | \
		(((unsigned long)fn) << GHCB_MSR_CPUID_FUNC_POS))

/* AP Reset Hold */
#define GHCB_MSR_AP_RESET_HOLD_REQ		0x006
#define GHCB_MSR_AP_RESET_HOLD_RESP		0x007

/* GHCB Hypervisor Feature Request/Response */
#define GHCB_MSR_HV_FT_REQ			0x080
#define GHCB_MSR_HV_FT_RESP			0x081

/* GHCB GPA Register */
#define GHCB_MSR_GPA_REG_REQ		0x012
#define GHCB_MSR_GPA_REG_VALUE_POS	12
#define GHCB_MSR_GPA_REG_GFN_MASK	GENMASK_ULL(51, 0)
#define GHCB_MSR_GPA_REQ_GFN_VAL(v)		\
	(((unsigned long)((v) & GHCB_MSR_GPA_REG_GFN_MASK) << GHCB_MSR_GPA_REG_VALUE_POS)| \
	GHCB_MSR_GPA_REG_REQ)

#define GHCB_MSR_GPA_REG_RESP		0x013
#define GHCB_MSR_GPA_REG_RESP_VAL(v)	((v) >> GHCB_MSR_GPA_REG_VALUE_POS)

/* SNP Page State Change */
#define GHCB_MSR_PSC_REQ		0x014
#define SNP_PAGE_STATE_PRIVATE		1
#define SNP_PAGE_STATE_SHARED		2
#define GHCB_MSR_PSC_GFN_POS		12
#define GHCB_MSR_PSC_GFN_MASK		GENMASK_ULL(39, 0)
#define GHCB_MSR_PSC_OP_POS		52
#define GHCB_MSR_PSC_OP_MASK		0xf
#define GHCB_MSR_PSC_REQ_GFN(gfn, op)	\
	(((unsigned long)((op) & GHCB_MSR_PSC_OP_MASK) << GHCB_MSR_PSC_OP_POS) | \
	((unsigned long)((gfn) & GHCB_MSR_PSC_GFN_MASK) << GHCB_MSR_PSC_GFN_POS) | \
	GHCB_MSR_PSC_REQ)

#define GHCB_MSR_PSC_RESP		0x015
#define GHCB_MSR_PSC_ERROR_POS		32
#define GHCB_MSR_PSC_RESP_VAL(val)	((val) >> GHCB_MSR_PSC_ERROR_POS)

/* GHCB Hypervisor Feature Request */
#define GHCB_MSR_HV_FT_REQ	0x080
#define GHCB_MSR_HV_FT_RESP	0x081
#define GHCB_MSR_HV_FT_POS	12
#define GHCB_MSR_HV_FT_MASK	GENMASK_ULL(51, 0)

#define GHCB_MSR_HV_FT_RESP_VAL(v)	\
	(((unsigned long)((v) >> GHCB_MSR_HV_FT_POS) & GHCB_MSR_HV_FT_MASK))

#define GHCB_HV_FT_SNP			BIT_ULL(0)

#define GHCB_MSR_TERM_REQ		0x100
#define GHCB_MSR_TERM_REASON_SET_POS	12
#define GHCB_MSR_TERM_REASON_SET_MASK	0xf
#define GHCB_MSR_TERM_REASON_POS	16
#define GHCB_MSR_TERM_REASON_MASK	0xff
#define GHCB_SEV_TERM_REASON(reason_set, reason_val)						  \
	(((((u64)reason_set) &  GHCB_MSR_TERM_REASON_SET_MASK) << GHCB_MSR_TERM_REASON_SET_POS) | \
	((((u64)reason_val) & GHCB_MSR_TERM_REASON_MASK) << GHCB_MSR_TERM_REASON_POS))

/* Error code from reason set 0 */
#define SEV_TERM_SET_GEN		0
#define GHCB_SEV_ES_GEN_REQ		0
#define GHCB_SEV_ES_PROT_UNSUPPORTED	1
#define GHCB_SNP_UNSUPPORTED		2

#define GHCB_RESP_CODE(v)		((v) & GHCB_MSR_INFO_MASK)

/* Linux specific reason codes (used with reason set 1) */
#define SEV_TERM_SET_LINUX		1
#define GHCB_TERM_REGISTER		0	/* GHCB GPA registration failure */
#define GHCB_TERM_PSC			1	/* Page State Change failure */
#define GHCB_TERM_PVALIDATE		2	/* Pvalidate failure */
#define GHCB_TERM_NOT_VMPL0		3	/* SNP guest is not running at VMPL-0 */

#endif
