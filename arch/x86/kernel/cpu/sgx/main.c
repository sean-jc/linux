// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.

#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include "arch.h"
#include "encls.h"
#include "sgx.h"

struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];
EXPORT_SYMBOL_GPL(sgx_epc_sections);
bool sgx_enabled;
EXPORT_SYMBOL_GPL(sgx_enabled);

int sgx_nr_epc_sections;

/* A per-cpu cache for the last known values of IA32_SGXLEPUBKEYHASHx MSRs. */
static DEFINE_PER_CPU(u64 [4], sgx_lepubkeyhash_cache);

static struct sgx_epc_page *sgx_section_try_take_page(
	struct sgx_epc_section *section)
{
	struct sgx_epc_page *page;

	if (!section->free_cnt)
		return NULL;

	page = list_first_entry(&section->page_list, struct sgx_epc_page,
				list);
	list_del_init(&page->list);
	section->free_cnt--;
	return page;
}

static struct sgx_epc_page *sgx_try_alloc_page(void *owner)
{
	struct sgx_epc_section *section;
	struct sgx_epc_page *page;
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++) {
		section = &sgx_epc_sections[i];
		spin_lock(&section->lock);
		page = sgx_section_try_take_page(section);
		spin_unlock(&section->lock);

		if (page) {
			page->owner = owner;
			return page;
		}
	}

	return NULL;
}

/**
 * sgx_alloc_page - Allocate an EPC page
 * @owner:	the owner of the EPC page
 * @reclaim:	reclaim pages if necessary
 *
 * Try to grab a page from the free EPC page list. If there is a free page
 * available, it is returned to the caller. The @reclaim parameter hints
 * the EPC memory manager to swap pages when required.
 *
 * Return:
 *   a pointer to a &struct sgx_epc_page instance,
 *   -errno on error
 */
struct sgx_epc_page *sgx_alloc_page(void *owner, bool reclaim)
{
	struct sgx_epc_page *entry;

	for ( ; ; ) {
		entry = sgx_try_alloc_page(owner);
		if (entry)
			break;

		if (list_empty(&sgx_active_page_list))
			return ERR_PTR(-ENOMEM);

		if (!reclaim) {
			entry = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current)) {
			entry = ERR_PTR(-ERESTARTSYS);
			break;
		}

		sgx_reclaim_pages();
		schedule();
	}

	if (sgx_calc_free_cnt() < SGX_NR_LOW_PAGES)
		wake_up(&ksgxswapd_waitq);

	return entry;
}
EXPORT_SYMBOL_GPL(sgx_alloc_page);

/**
 * __sgx_free_page - Free an EPC page
 * @page:	pointer a previously allocated EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages.  If the
 * page is reclaimable, delete it from the active page list.
 *
 * Return:
 *   0 on success
 *   -EBUSY if the page cannot be removed from the active list
 *   SGX error code if EREMOVE fails
 */
int __sgx_free_page(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = sgx_epc_section(page);
	int ret;

	/*
	 * Remove the page from the active list if necessary.  If the page
	 * is actively being reclaimed, i.e. RECLAIMABLE is set but the
	 * page isn't on the active list, return -EBUSY as we can't free
	 * the page at this time since it is "owned" by the reclaimer.
	 */
	spin_lock(&sgx_active_page_list_lock);
	if (page->desc & SGX_EPC_PAGE_RECLAIMABLE) {
		if (list_empty(&page->list)) {
			spin_unlock(&sgx_active_page_list_lock);
			return -EBUSY;
		}
		list_del(&page->list);
		page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;
	}
	spin_unlock(&sgx_active_page_list_lock);

	ret = __eremove(sgx_epc_addr(page));
	if (ret)
		return ret;

	spin_lock(&section->lock);
	list_add_tail(&page->list, &section->page_list);
	section->free_cnt++;
	spin_unlock(&section->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(__sgx_free_page);

/**
 * sgx_free_page - Free an EPC page and WARN on failure
 * @page:	pointer to a previously allocated EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages, and WARN
 * if EREMOVE fails.  For use when the call site cannot (or chooses not to)
 * handle failure, i.e. the page is leaked on failure.
 */
void sgx_free_page(struct sgx_epc_page *page)
{
	int ret;

	ret = __sgx_free_page(page);
	WARN(ret < 0, "sgx: cannot free page, reclaim in-progress");
	WARN(ret > 0, "sgx: EREMOVE returned %d (0x%x)", ret, ret);
}
EXPORT_SYMBOL_GPL(sgx_free_page);

static void sgx_update_lepubkeyhash_msrs(u64 *lepubkeyhash, bool enforce)
{
	u64 *cache;
	int i;

	cache = per_cpu(sgx_lepubkeyhash_cache, smp_processor_id());
	for (i = 0; i < 4; i++) {
		if (enforce || (lepubkeyhash[i] != cache[i])) {
			wrmsrl(MSR_IA32_SGXLEPUBKEYHASH0 + i, lepubkeyhash[i]);
			cache[i] = lepubkeyhash[i];
		}
	}
}

/**
 * sgx_einit - initialize an enclave
 * @sigstruct:		a pointer a SIGSTRUCT
 * @token:		a pointer an EINITTOKEN (optional)
 * @secs:		a pointer a SECS
 * @lepubkeyhash:	the desired value for IA32_SGXLEPUBKEYHASHx MSRs
 *
 * Execute ENCLS[EINIT], writing the IA32_SGXLEPUBKEYHASHx MSRs according
 * to @lepubkeyhash (if possible and necessary).
 *
 * Return:
 *   0 on success,
 *   -errno or SGX error on failure
 */
int sgx_einit(struct sgx_sigstruct *sigstruct, struct sgx_einittoken *token,
	      struct sgx_epc_page *secs, u64 *lepubkeyhash)
{
	int ret;

	if (!boot_cpu_has(X86_FEATURE_SGX_LC))
		return __einit(sigstruct, token, sgx_epc_addr(secs));

	preempt_disable();
	sgx_update_lepubkeyhash_msrs(lepubkeyhash, false);
	ret = __einit(sigstruct, token, sgx_epc_addr(secs));
	if (ret == SGX_INVALID_EINITTOKEN) {
		sgx_update_lepubkeyhash_msrs(lepubkeyhash, true);
		ret = __einit(sigstruct, token, sgx_epc_addr(secs));
	}
	preempt_enable();
	return ret;
}
EXPORT_SYMBOL(sgx_einit);

static __init void sgx_free_epc_section(struct sgx_epc_section *section)
{
	struct sgx_epc_page *page;

	while (!list_empty(&section->page_list)) {
		page = list_first_entry(&section->page_list,
					struct sgx_epc_page, list);
		list_del(&page->list);
		kfree(page);
	}

	while (!list_empty(&section->unsanitized_page_list)) {
		page = list_first_entry(&section->unsanitized_page_list,
					struct sgx_epc_page, list);
		list_del(&page->list);
		kfree(page);
	}

	memunmap(section->va);
}

static __init int sgx_init_epc_section(u64 addr, u64 size, unsigned long index,
				       struct sgx_epc_section *section)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	struct sgx_epc_page *page;
	unsigned long i;

	section->va = memremap(addr, size, MEMREMAP_WB);
	if (!section->va)
		return -ENOMEM;

	section->pa = addr;
	spin_lock_init(&section->lock);
	INIT_LIST_HEAD(&section->page_list);
	INIT_LIST_HEAD(&section->unsanitized_page_list);

	for (i = 0; i < nr_pages; i++) {
		page = kzalloc(sizeof(*page), GFP_KERNEL);
		if (!page)
			goto out;
		page->desc = (addr + (i << PAGE_SHIFT)) | index;
		list_add_tail(&page->list, &section->unsanitized_page_list);
		section->free_cnt++;
	}

	return 0;
out:
	sgx_free_epc_section(section);
	return -ENOMEM;
}

static __init void sgx_page_cache_teardown(void)
{
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++)
		sgx_free_epc_section(&sgx_epc_sections[i]);
}

/**
 * A section metric is concatenated in a way that @low bits 12-31 define the
 * bits 12-31 of the metric and @high bits 0-19 define the bits 32-51 of the
 * metric.
 */
static inline u64 sgx_calc_section_metric(u64 low, u64 high)
{
	return (low & GENMASK_ULL(31, 12)) +
	       ((high & GENMASK_ULL(19, 0)) << 32);
}

static __init int sgx_page_cache_init(void)
{
	u32 eax, ebx, ecx, edx, type;
	u64 pa, size;
	int ret;
	int i;

	BUILD_BUG_ON(SGX_MAX_EPC_SECTIONS > (SGX_EPC_SECTION_MASK + 1));

	for (i = 0; i < (SGX_MAX_EPC_SECTIONS + 1); i++) {
		cpuid_count(SGX_CPUID, i + SGX_CPUID_FIRST_VARIABLE_SUB_LEAF,
			    &eax, &ebx, &ecx, &edx);

		type = eax & SGX_CPUID_SUB_LEAF_TYPE_MASK;
		if (type == SGX_CPUID_SUB_LEAF_INVALID)
			break;
		if (type != SGX_CPUID_SUB_LEAF_EPC_SECTION) {
			pr_err_once("sgx: Unknown sub-leaf type: %u\n", type);
			return -ENODEV;
		}
		if (i == SGX_MAX_EPC_SECTIONS) {
			pr_warn("sgx: More than "
				__stringify(SGX_MAX_EPC_SECTIONS)
				" EPC sections\n");
			break;
		}

		pa = sgx_calc_section_metric(eax, ebx);
		size = sgx_calc_section_metric(ecx, edx);
		pr_info("sgx: EPC section 0x%llx-0x%llx\n", pa, pa + size - 1);

		ret = sgx_init_epc_section(pa, size, i, &sgx_epc_sections[i]);
		if (ret) {
			sgx_page_cache_teardown();
			return ret;
		}

		sgx_nr_epc_sections++;
	}

	if (!sgx_nr_epc_sections) {
		pr_err("sgx: There are zero EPC sections.\n");
		return -ENODEV;
	}

	return 0;
}

static __init int sgx_init(void)
{
	int ret;

	if (!boot_cpu_has(X86_FEATURE_SGX))
		return false;

	ret = sgx_page_cache_init();
	if (ret)
		return ret;

	ret = sgx_page_reclaimer_init();
	if (ret) {
		sgx_page_cache_teardown();
		return ret;
	}

	sgx_enabled = true;
	return 0;
}

arch_initcall(sgx_init);
