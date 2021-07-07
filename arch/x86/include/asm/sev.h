/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#ifndef __ASM_ENCRYPTED_STATE_H
#define __ASM_ENCRYPTED_STATE_H

#include <linux/types.h>
#include <linux/sev.h>
#include <asm/insn.h>
#include <asm/sev-common.h>
#include <asm/bootparam.h>

#define GHCB_PROTOCOL_MIN	1ULL
#define GHCB_PROTOCOL_MAX	2ULL
#define GHCB_DEFAULT_USAGE	0ULL

#define	VMGEXIT()			{ asm volatile("rep; vmmcall\n\r"); }

enum es_result {
	ES_OK,			/* All good */
	ES_UNSUPPORTED,		/* Requested operation not supported */
	ES_VMM_ERROR,		/* Unexpected state from the VMM */
	ES_DECODE_FAILED,	/* Instruction decoding failed */
	ES_EXCEPTION,		/* Instruction caused exception */
	ES_RETRY,		/* Retry instruction emulation */
};

struct es_fault_info {
	unsigned long vector;
	unsigned long error_code;
	unsigned long cr2;
};

struct pt_regs;

/* ES instruction emulation context */
struct es_em_ctxt {
	struct pt_regs *regs;
	struct insn insn;
	struct es_fault_info fi;
};

void do_vc_no_ghcb(struct pt_regs *regs, unsigned long exit_code);

/* AMD SEV Confidential computing blob structure */
#define CC_BLOB_SEV_HDR_MAGIC	0x45444d41
struct cc_blob_sev_info {
	u32 magic;
	u16 version;
	u16 reserved;
	u64 secrets_phys;
	u32 secrets_len;
	u64 cpuid_phys;
	u32 cpuid_len;
};

static inline u64 lower_bits(u64 val, unsigned int bits)
{
	u64 mask = (1ULL << bits) - 1;

	return (val & mask);
}

struct real_mode_header;
enum stack_type;

/* Early IDT entry points for #VC handler */
extern void vc_no_ghcb(void);
extern void vc_boot_ghcb(void);
extern bool handle_vc_boot_ghcb(struct pt_regs *regs);

/* Software defined (when rFlags.CF = 1) */
#define PVALIDATE_FAIL_NOUPDATE		255

#define RMPADJUST_VMSA_PAGE_BIT		BIT(16)

#ifdef CONFIG_AMD_MEM_ENCRYPT
extern struct static_key_false sev_es_enable_key;
extern void __sev_es_ist_enter(struct pt_regs *regs);
extern void __sev_es_ist_exit(void);
static __always_inline void sev_es_ist_enter(struct pt_regs *regs)
{
	if (static_branch_unlikely(&sev_es_enable_key))
		__sev_es_ist_enter(regs);
}
static __always_inline void sev_es_ist_exit(void)
{
	if (static_branch_unlikely(&sev_es_enable_key))
		__sev_es_ist_exit();
}
extern int sev_es_setup_ap_jump_table(struct real_mode_header *rmh);
extern void __sev_es_nmi_complete(void);
static __always_inline void sev_es_nmi_complete(void)
{
	if (static_branch_unlikely(&sev_es_enable_key))
		__sev_es_nmi_complete();
}
extern int __init sev_es_efi_map_ghcbs(pgd_t *pgd);
static inline int pvalidate(unsigned long vaddr, bool rmp_psize, bool validate)
{
	bool no_rmpupdate;
	int rc;

	/* "pvalidate" mnemonic support in binutils 2.36 and newer */
	asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFF\n\t"
		     CC_SET(c)
		     : CC_OUT(c) (no_rmpupdate), "=a"(rc)
		     : "a"(vaddr), "c"(rmp_psize), "d"(validate)
		     : "memory", "cc");

	if (no_rmpupdate)
		return PVALIDATE_FAIL_NOUPDATE;

	return rc;
}
void __init early_snp_set_memory_private(unsigned long vaddr, unsigned long paddr,
					 unsigned int npages);
void __init early_snp_set_memory_shared(unsigned long vaddr, unsigned long paddr,
					unsigned int npages);
void __init snp_prep_memory(unsigned long paddr, unsigned int sz, int op);
void snp_set_memory_shared(unsigned long vaddr, unsigned int npages);
void snp_set_memory_private(unsigned long vaddr, unsigned int npages);
void snp_set_wakeup_secondary_cpu(void);

#ifdef __BOOT_COMPRESSED
bool sev_snp_enabled(void);
#endif

void sev_snp_cpuid_init(struct boot_params *bp);
#ifndef __BOOT_COMPRESSED
void sev_snp_cpuid_init_virtual(void);
void sev_snp_cpuid_init_remap_early(void);
#endif /* __BOOT_COMPRESSED */
#else
static inline void sev_es_ist_enter(struct pt_regs *regs) { }
static inline void sev_es_ist_exit(void) { }
static inline int sev_es_setup_ap_jump_table(struct real_mode_header *rmh) { return 0; }
static inline void sev_es_nmi_complete(void) { }
static inline int sev_es_efi_map_ghcbs(pgd_t *pgd) { return 0; }
static inline int pvalidate(unsigned long vaddr, bool rmp_psize, bool validate) { return 0; }
static inline void __init
early_snp_set_memory_private(unsigned long vaddr, unsigned long paddr, unsigned int npages) { }
static inline void __init
early_snp_set_memory_shared(unsigned long vaddr, unsigned long paddr, unsigned int npages) { }
static inline void __init snp_prep_memory(unsigned long paddr, unsigned int sz, int op) { }
static inline void snp_set_memory_shared(unsigned long vaddr, unsigned int npages) { }
static inline void snp_set_memory_private(unsigned long vaddr, unsigned int npages) { }
static inline void snp_set_wakeup_secondary_cpu(void) { }

#ifdef __BOOT_COMPRESSED
static inline bool sev_snp_enabled { return false; }
#endif

static inline void sev_snp_cpuid_init(struct boot_params *bp) { }
#ifndef __BOOT_COMPRESSED
static inline void sev_snp_cpuid_init_virtual(void) { }
static inline void sev_snp_cpuid_init_remap_early(void) { }
#endif /* __BOOT_COMPRESSED */
#endif

#endif
