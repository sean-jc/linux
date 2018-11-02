// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-19 Intel Corporation.

#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include "driver/driver.h"
#include "sgx.h"

LIST_HEAD(sgx_active_page_list);
DEFINE_SPINLOCK(sgx_active_page_list_lock);
DECLARE_WAIT_QUEUE_HEAD(ksgxswapd_waitq);

static struct task_struct *ksgxswapd_tsk;

static void sgx_sanitize_section(struct sgx_epc_section *section)
{
	struct sgx_epc_page *page, *tmp;
	LIST_HEAD(secs_list);
	int ret;

	while (!list_empty(&section->unsanitized_page_list)) {
		if (kthread_should_stop())
			return;

		spin_lock(&section->lock);

		page = list_first_entry(&section->unsanitized_page_list,
					struct sgx_epc_page, list);

		ret = __eremove(sgx_epc_addr(page));
		if (!ret)
			list_move(&page->list, &section->page_list);
		else
			list_move_tail(&page->list, &secs_list);

		spin_unlock(&section->lock);

		cond_resched();
	}

	list_for_each_entry_safe(page, tmp, &secs_list, list) {
		if (kthread_should_stop())
			return;

		ret = __eremove(sgx_epc_addr(page));
		if (!WARN_ON_ONCE(ret)) {
			spin_lock(&section->lock);
			list_move(&page->list, &section->page_list);
			spin_unlock(&section->lock);
		} else {
			list_del(&page->list);
			kfree(page);
		}

		cond_resched();
	}
}

static inline bool sgx_should_reclaim(void)
{
	return sgx_calc_free_cnt() < SGX_NR_HIGH_PAGES &&
	       !list_empty(&sgx_active_page_list);
}

static int ksgxswapd(void *p)
{
	int i;

	set_freezable();

	for (i = 0; i < sgx_nr_epc_sections; i++)
		sgx_sanitize_section(&sgx_epc_sections[i]);

	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		wait_event_freezable(ksgxswapd_waitq, kthread_should_stop() ||
						      sgx_should_reclaim());

		if (sgx_should_reclaim())
			sgx_reclaim_pages();

		cond_resched();
	}

	return 0;
}

int sgx_page_reclaimer_init(void)
{
	struct task_struct *tsk;

	tsk = kthread_run(ksgxswapd, NULL, "ksgxswapd");
	if (IS_ERR(tsk))
		return PTR_ERR(tsk);

	ksgxswapd_tsk = tsk;

	return 0;
}

/**
 * sgx_mark_page_reclaimable() - Mark a page as reclaimable
 * @page:	EPC page
 *
 * Mark a page as reclaimable and add it to the active page list. Pages
 * are automatically removed from the active list when freed.
 */
void sgx_mark_page_reclaimable(struct sgx_epc_page *page)
{
	spin_lock(&sgx_active_page_list_lock);
	page->desc |= SGX_EPC_PAGE_RECLAIMABLE;
	list_add_tail(&page->list, &sgx_active_page_list);
	spin_unlock(&sgx_active_page_list_lock);
}
EXPORT_SYMBOL_GPL(sgx_mark_page_reclaimable);

bool sgx_reclaimer_get(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *encl_page = epc_page->owner;
	struct sgx_encl *encl = encl_page->encl;

	return kref_get_unless_zero(&encl->refcount) != 0;
}

void sgx_reclaimer_put(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *encl_page = epc_page->owner;
	struct sgx_encl *encl = encl_page->encl;

	kref_put(&encl->refcount, sgx_encl_release);
}

static bool sgx_reclaimer_evict(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *page = epc_page->owner;
	struct sgx_encl *encl = page->encl;
	struct sgx_encl_mm *encl_mm = NULL;
	struct sgx_encl_mm *prev_mm = NULL;
	bool ret = true;
	int iter;

	while (true) {
		encl_mm = sgx_encl_next_mm(encl, prev_mm, &iter);
		if (prev_mm)
			kref_put(&prev_mm->refcount, sgx_encl_mm_release);
		prev_mm = encl_mm;

		if (iter == SGX_ENCL_MM_ITER_DONE)
			break;

		if (iter == SGX_ENCL_MM_ITER_RESTART)
			continue;

		if (!mmget_not_zero(encl_mm->mm))
			continue;

		down_read(&encl_mm->mm->mmap_sem);
		ret = !sgx_encl_test_and_clear_young(encl_mm->mm, page);
		up_read(&encl_mm->mm->mmap_sem);

		mmput(encl_mm->mm);

		if (!ret || (encl->flags & SGX_ENCL_DEAD)) {
			kref_put(&encl_mm->refcount, sgx_encl_mm_release);
			break;
		}
	}

	/*
	 * Do not reclaim this page if it has been recently accessed by any
	 * mm_struct *and* if the enclave is still alive.  No need to take
	 * the enclave's lock, worst case scenario reclaiming pages from a
	 * dead enclave is delayed slightly.  A live enclave with a recently
	 * accessed page is more common and avoiding lock contention in that
	 * case is a boon to performance.
	 */
	if (!ret && !(encl->flags & SGX_ENCL_DEAD))
		return false;

	mutex_lock(&encl->lock);
	page->desc |= SGX_ENCL_PAGE_RECLAIMED;
	mutex_unlock(&encl->lock);

	return true;
}

static void sgx_reclaimer_block(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *page = epc_page->owner;
	unsigned long addr = SGX_ENCL_PAGE_ADDR(page);
	struct sgx_encl *encl = page->encl;
	struct sgx_encl_mm *encl_mm = NULL;
	struct sgx_encl_mm *prev_mm = NULL;
	struct vm_area_struct *vma;
	int iter;
	int ret;

	while (true) {
		encl_mm = sgx_encl_next_mm(encl, prev_mm, &iter);
		if (prev_mm)
			kref_put(&prev_mm->refcount, sgx_encl_mm_release);
		prev_mm = encl_mm;

		if (iter == SGX_ENCL_MM_ITER_DONE)
			break;

		if (iter == SGX_ENCL_MM_ITER_RESTART)
			continue;

		if (!mmget_not_zero(encl_mm->mm))
			continue;

		down_read(&encl_mm->mm->mmap_sem);

		ret = sgx_encl_find(encl_mm->mm, addr, &vma);
		if (!ret && encl == vma->vm_private_data)
			zap_vma_ptes(vma, addr, PAGE_SIZE);

		up_read(&encl_mm->mm->mmap_sem);

		mmput(encl_mm->mm);
	}

	mutex_lock(&encl->lock);

	if (!(encl->flags & SGX_ENCL_DEAD)) {
		ret = __eblock(sgx_epc_addr(epc_page));
		if (encls_failed(ret))
			ENCLS_WARN(ret, "EBLOCK");
	}

	mutex_unlock(&encl->lock);
}

static int __sgx_encl_ewb(struct sgx_encl *encl, struct sgx_epc_page *epc_page,
			  struct sgx_va_page *va_page, unsigned int va_offset)
{
	struct sgx_encl_page *encl_page = epc_page->owner;
	pgoff_t page_index = sgx_encl_get_index(encl, encl_page);
	pgoff_t pcmd_index = sgx_pcmd_index(encl, page_index);
	unsigned long pcmd_offset = sgx_pcmd_offset(page_index);
	struct sgx_pageinfo pginfo;
	struct page *backing;
	struct page *pcmd;
	int ret;

	backing = sgx_encl_get_backing_page(encl, page_index);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		goto err_backing;
	}

	pcmd = sgx_encl_get_backing_page(encl, pcmd_index);
	if (IS_ERR(pcmd)) {
		ret = PTR_ERR(pcmd);
		goto err_pcmd;
	}

	pginfo.addr = 0;
	pginfo.contents = (unsigned long)kmap_atomic(backing);
	pginfo.metadata = (unsigned long)kmap_atomic(pcmd) + pcmd_offset;
	pginfo.secs = 0;
	ret = __ewb(&pginfo, sgx_epc_addr(epc_page),
		    sgx_epc_addr(va_page->epc_page) + va_offset);
	kunmap_atomic((void *)(unsigned long)(pginfo.metadata - pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	set_page_dirty(pcmd);
	put_page(pcmd);
	set_page_dirty(backing);

err_pcmd:
	put_page(backing);

err_backing:
	return ret;
}

static void sgx_ipi_cb(void *info)
{
}

static const cpumask_t *sgx_encl_ewb_cpumask(struct sgx_encl *encl)
{
	cpumask_t *cpumask = &encl->cpumask;
	struct sgx_encl_mm *encl_mm = NULL;
	struct sgx_encl_mm *prev_mm = NULL;
	int iter;

	cpumask_clear(cpumask);

	while (true) {
		encl_mm = sgx_encl_next_mm(encl, prev_mm, &iter);
		if (prev_mm)
			kref_put(&prev_mm->refcount, sgx_encl_mm_release);
		prev_mm = encl_mm;

		if (iter == SGX_ENCL_MM_ITER_DONE)
			break;

		if (iter == SGX_ENCL_MM_ITER_RESTART)
			continue;

		if (!mmget_not_zero(encl_mm->mm))
			continue;

		cpumask_or(cpumask, cpumask, mm_cpumask(encl_mm->mm));

		mmput(encl_mm->mm);
	}

	return cpumask;
}

static void sgx_encl_ewb(struct sgx_epc_page *epc_page, bool do_free)
{
	struct sgx_encl_page *encl_page = epc_page->owner;
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_va_page *va_page;
	unsigned int va_offset;
	int ret;

	encl_page->desc &= ~SGX_ENCL_PAGE_RECLAIMED;

	if (!(encl->flags & SGX_ENCL_DEAD)) {
		va_page = list_first_entry(&encl->va_pages, struct sgx_va_page,
					   list);
		va_offset = sgx_alloc_va_slot(va_page);
		if (sgx_va_page_full(va_page))
			list_move_tail(&va_page->list, &encl->va_pages);

		ret = __sgx_encl_ewb(encl, epc_page, va_page, va_offset);
		if (ret == SGX_NOT_TRACKED) {
			ret = __etrack(sgx_epc_addr(encl->secs.epc_page));
			if (ret) {
				if (encls_failed(ret) ||
				    encls_returned_code(ret))
					ENCLS_WARN(ret, "ETRACK");
			}

			ret = __sgx_encl_ewb(encl, epc_page, va_page,
					     va_offset);
			if (ret == SGX_NOT_TRACKED) {
				/*
				 * Slow path, send IPIs to kick cpus out of the
				 * enclave.  Note, it's imperative that the cpu
				 * mask is generated *after* ETRACK, else we'll
				 * miss cpus that entered the enclave between
				 * generating the mask and incrementing epoch.
				 */
				on_each_cpu_mask(sgx_encl_ewb_cpumask(encl),
						 sgx_ipi_cb, NULL, 1);
				ret = __sgx_encl_ewb(encl, epc_page, va_page,
						     va_offset);
			}
		}

		if (ret)
			if (encls_failed(ret) || encls_returned_code(ret))
				ENCLS_WARN(ret, "EWB");

		encl_page->desc |= va_offset;
		encl_page->va_page = va_page;
	} else if (!do_free) {
		ret = __eremove(sgx_epc_addr(epc_page));
		WARN(ret, "EREMOVE returned %d\n", ret);
	}

	if (do_free)
		sgx_free_page(epc_page);

	encl_page->epc_page = NULL;
}

static void sgx_reclaimer_write(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *encl_page = epc_page->owner;
	struct sgx_encl *encl = encl_page->encl;

	mutex_lock(&encl->lock);

	sgx_encl_ewb(epc_page, false);
	encl->secs_child_cnt--;
	if (!encl->secs_child_cnt &&
	    (encl->flags & (SGX_ENCL_DEAD | SGX_ENCL_INITIALIZED))) {
		sgx_encl_ewb(encl->secs.epc_page, true);
	}

	mutex_unlock(&encl->lock);
}

/**
 * sgx_reclaim_pages() - Reclaim EPC pages from the consumers
 * Takes a fixed chunk of pages from the global list of consumed EPC pages and
 * tries to swap them. Only the pages that are either being freed by the
 * consumer or actively used are skipped.
 */
void sgx_reclaim_pages(void)
{
	struct sgx_epc_page *chunk[SGX_NR_TO_SCAN + 1];
	struct sgx_epc_page *epc_page;
	struct sgx_epc_section *section;
	int i, j;

	spin_lock(&sgx_active_page_list_lock);
	for (i = 0, j = 0; i < SGX_NR_TO_SCAN; i++) {
		if (list_empty(&sgx_active_page_list))
			break;

		epc_page = list_first_entry(&sgx_active_page_list,
					    struct sgx_epc_page, list);
		list_del_init(&epc_page->list);

		if (sgx_reclaimer_get(epc_page))
			chunk[j++] = epc_page;
		else
			/* The owner is freeing the page. No need to add the
			 * page back to the list of reclaimable pages.
			 */
			epc_page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;
	}
	spin_unlock(&sgx_active_page_list_lock);

	for (i = 0; i < j; i++) {
		epc_page = chunk[i];
		if (sgx_reclaimer_evict(epc_page))
			continue;

		sgx_reclaimer_put(epc_page);

		spin_lock(&sgx_active_page_list_lock);
		list_add_tail(&epc_page->list, &sgx_active_page_list);
		spin_unlock(&sgx_active_page_list_lock);

		chunk[i] = NULL;
	}

	for (i = 0; i < j; i++) {
		epc_page = chunk[i];
		if (epc_page)
			sgx_reclaimer_block(epc_page);
	}

	for (i = 0; i < j; i++) {
		epc_page = chunk[i];
		if (epc_page) {
			sgx_reclaimer_write(epc_page);
			sgx_reclaimer_put(epc_page);
			epc_page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;

			section = sgx_epc_section(epc_page);

			spin_lock(&section->lock);
			list_add_tail(&epc_page->list,
				      &section->page_list);
			section->free_cnt++;
			spin_unlock(&section->lock);
		}
	}
}

unsigned long sgx_calc_free_cnt(void)
{
	struct sgx_epc_section *section;
	unsigned long free_cnt = 0;
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++) {
		section = &sgx_epc_sections[i];
		free_cnt += section->free_cnt;
	}

	return free_cnt;
}
