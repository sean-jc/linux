/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD Secure Encrypted Virtualization
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#ifndef __LINUX_SEV_H
#define __LINUX_SEV_H

struct __packed rmpentry {
	union {
		struct {
			u64	assigned	: 1,
				pagesize	: 1,
				immutable	: 1,
				rsvd1		: 9,
				gpa		: 39,
				asid		: 10,
				vmsa		: 1,
				validated	: 1,
				rsvd2		: 1;
		} info;
		u64 low;
	};
	u64 high;
};

#define rmpentry_assigned(x)	((x)->info.assigned)
#define rmpentry_pagesize(x)	((x)->info.pagesize)
#define rmpentry_vmsa(x)	((x)->info.vmsa)
#define rmpentry_asid(x)	((x)->info.asid)
#define rmpentry_validated(x)	((x)->info.validated)
#define rmpentry_gpa(x)		((unsigned long)(x)->info.gpa)
#define rmpentry_immutable(x)	((x)->info.immutable)

/* RMP page size */
#define RMP_PG_SIZE_4K			0

#define RMP_TO_X86_PG_LEVEL(level)	(((level) == RMP_PG_SIZE_4K) ? PG_LEVEL_4K : PG_LEVEL_2M)

#ifdef CONFIG_AMD_MEM_ENCRYPT
struct rmpentry *snp_lookup_page_in_rmptable(struct page *page, int *level);
#else
static inline struct rmpentry *snp_lookup_page_in_rmptable(struct page *page, int *level)
{
	return NULL;
}

#endif /* CONFIG_AMD_MEM_ENCRYPT */
#endif /* __LINUX_SEV_H */
