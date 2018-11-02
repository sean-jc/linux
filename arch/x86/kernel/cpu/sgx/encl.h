/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/**
 * Copyright(c) 2016-19 Intel Corporation.
 */
#ifndef _X86_ENCL_H
#define _X86_ENCL_H

#include <linux/cpumask.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/radix-tree.h>
#include <linux/workqueue.h>

/**
 * enum sgx_encl_page_desc - defines bits for an enclave page's descriptor
 * %SGX_ENCL_PAGE_TCS:			The page is a TCS page.
 * %SGX_ENCL_PAGE_ADDR_MASK:		Holds the virtual address of the page.
 *
 * The page address for SECS is zero and is used by the subsystem to recognize
 * the SECS page.
 */
enum sgx_encl_page_desc {
	SGX_ENCL_PAGE_TCS		= BIT(0),
	/* Bits 11:3 are available when the page is not swapped. */
	SGX_ENCL_PAGE_ADDR_MASK		= PAGE_MASK,
};

#define SGX_ENCL_PAGE_ADDR(encl_page) \
	((encl_page)->desc & SGX_ENCL_PAGE_ADDR_MASK)
#define SGX_ENCL_PAGE_VA_OFFSET(encl_page) \
	((encl_page)->desc & SGX_ENCL_PAGE_VA_OFFSET_MASK)

struct sgx_encl_page {
	unsigned long desc;
	struct sgx_epc_page *epc_page;
	struct sgx_encl *encl;
};

enum sgx_encl_flags {
	SGX_ENCL_CREATED	= BIT(0),
	SGX_ENCL_INITIALIZED	= BIT(1),
	SGX_ENCL_DEBUG		= BIT(2),
	SGX_ENCL_SUSPEND	= BIT(3),
	SGX_ENCL_DEAD		= BIT(4),
};

struct sgx_encl_mm {
	struct sgx_encl *encl;
	struct mm_struct *mm;
	struct kref refcount;
	struct list_head list;
};

struct sgx_encl {
	unsigned int flags;
	u64 secs_attributes;
	u64 allowed_attributes;
	unsigned int page_cnt;
	unsigned int secs_child_cnt;
	struct mutex lock;
	struct list_head mm_list;
	spinlock_t mm_lock;
	struct file *backing;
	struct kref refcount;
	unsigned long base;
	unsigned long size;
	unsigned long ssaframesize;
	struct radix_tree_root page_tree;
	struct list_head add_page_reqs;
	struct work_struct work;
	struct sgx_encl_page secs;
	struct notifier_block pm_notifier;
};

extern const struct vm_operations_struct sgx_vm_ops;

enum sgx_encl_mm_iter {
	SGX_ENCL_MM_ITER_DONE		= 0,
	SGX_ENCL_MM_ITER_NEXT		= 1,
	SGX_ENCL_MM_ITER_RESTART	= 2,
};

int sgx_encl_find(struct mm_struct *mm, unsigned long addr,
		  struct vm_area_struct **vma);
void sgx_encl_destroy(struct sgx_encl *encl);
void sgx_encl_release(struct kref *ref);
pgoff_t sgx_encl_get_index(struct sgx_encl *encl, struct sgx_encl_page *page);
struct page *sgx_encl_get_backing_page(struct sgx_encl *encl, pgoff_t index);
struct sgx_encl_mm *sgx_encl_next_mm(struct sgx_encl *encl,
				     struct sgx_encl_mm *encl_mm, int *iter);
struct sgx_encl_mm *sgx_encl_mm_add(struct sgx_encl *encl,
				    struct mm_struct *mm);
void sgx_encl_mm_release(struct kref *ref);

#endif /* _X86_ENCL_H */
