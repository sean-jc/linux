// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <linux/highmem.h>
#include <linux/sched/mm.h>
#include "driver.h"

static int sgx_eldu(struct sgx_encl_page *encl_page,
		    struct sgx_epc_page *epc_page)
{
	struct sgx_encl *encl = encl_page->encl;
	pgoff_t page_index = sgx_encl_get_index(encl, encl_page);
	unsigned long pcmd_offset =
		(page_index & (PAGE_SIZE / sizeof(struct sgx_pcmd) - 1)) *
		sizeof(struct sgx_pcmd);
	unsigned long backing_addr = encl->backing + PAGE_SIZE * page_index;
	unsigned long addr = SGX_ENCL_PAGE_ADDR(encl_page);
	struct sgx_pageinfo pginfo;
	unsigned long va_offset;
	struct page *backing;
	struct page *pcmd;
	int ret;

	va_offset = SGX_ENCL_PAGE_VA_OFFSET(encl_page);

	ret = get_user_pages_remote(NULL, encl->mm, backing_addr, 1, 0,
				    &backing, NULL, NULL);
	if (ret < 0)
		return ret;

	pcmd = sgx_get_backing(encl->pcmd, page_index >> 5);
	if (IS_ERR(pcmd)) {
		put_page(backing);
		return PTR_ERR(pcmd);
	}

	pginfo.addr = addr;
	pginfo.contents = (unsigned long)kmap_atomic(backing);
	pginfo.metadata = (unsigned long)kmap_atomic(pcmd) + pcmd_offset;
	pginfo.secs = addr ? (unsigned long)sgx_epc_addr(encl->secs.epc_page) :
		      0;

	ret = __eldu(&pginfo, sgx_epc_addr(epc_page),
		     sgx_epc_addr(encl_page->va_page->epc_page) + va_offset);
	if (ret) {
		SGX_INVD(ret, encl, "ELDU returned %d (0x%x)", ret, ret);
		ret = encls_to_err(ret);
	}

	kunmap_atomic((void *)(unsigned long)(pginfo.metadata - pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	sgx_put_backing(pcmd, false);
	put_page(backing);
	return ret;
}

static struct sgx_epc_page *sgx_load_page(struct sgx_encl_page *encl_page)
{
	unsigned long va_offset = SGX_ENCL_PAGE_VA_OFFSET(encl_page);
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_epc_page *epc_page;
	int ret;

	epc_page = sgx_alloc_page();
	if (IS_ERR(epc_page))
		return epc_page;
	ret = sgx_eldu(encl_page, epc_page);
	if (ret) {
		sgx_free_page(epc_page);
		return ERR_PTR(ret);
	}
	sgx_free_va_slot(encl_page->va_page, va_offset);
	list_move(&encl_page->va_page->list, &encl->va_pages);
	encl_page->desc &= ~SGX_ENCL_PAGE_VA_OFFSET_MASK;
	sgx_set_page_loaded(encl_page, epc_page);
	return epc_page;
}

static struct sgx_encl_page *sgx_try_fault_page(struct vm_area_struct *vma,
						unsigned long addr,
						bool do_reserve)
{
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_epc_page *epc_page;
	struct sgx_encl_page *entry;
	int rc = 0;

	if ((encl->flags & SGX_ENCL_DEAD) ||
	    !(encl->flags & SGX_ENCL_INITIALIZED))
		return ERR_PTR(-EFAULT);

	entry = radix_tree_lookup(&encl->page_tree, addr >> PAGE_SHIFT);
	if (!entry)
		return ERR_PTR(-EFAULT);

	/* Page is already resident in the EPC. */
	if (entry->desc & SGX_ENCL_PAGE_LOADED) {
		if (entry->desc & SGX_ENCL_PAGE_RESERVED) {
			sgx_dbg(encl, "EPC page 0x%p is already reserved\n",
				(void *)SGX_ENCL_PAGE_ADDR(entry));
			return ERR_PTR(-EBUSY);
		}
		if (entry->desc & SGX_ENCL_PAGE_RECLAIMED) {
			sgx_dbg(encl, "EPC page 0x%p is being reclaimed\n",
				(void *)SGX_ENCL_PAGE_ADDR(entry));
			return ERR_PTR(-EBUSY);
		}
		if (do_reserve)
			entry->desc |= SGX_ENCL_PAGE_RESERVED;
		return entry;
	}

	if (!(encl->secs.desc & SGX_ENCL_PAGE_LOADED)) {
		epc_page = sgx_load_page(&encl->secs);
		if (IS_ERR(epc_page))
			return ERR_CAST(epc_page);
	}
	epc_page = sgx_load_page(entry);
	if (IS_ERR(epc_page))
		return ERR_CAST(epc_page);

	encl->secs_child_cnt++;
	sgx_test_and_clear_young(entry);
	if (do_reserve)
		entry->desc |= SGX_ENCL_PAGE_RESERVED;

	rc = vmf_insert_pfn(vma, addr, PFN_DOWN(entry->epc_page->desc));
	if (rc != VM_FAULT_NOPAGE) {
		sgx_invalidate(encl, true);
		return ERR_PTR(-EFAULT);
	}

	return entry;
}

struct sgx_encl_page *sgx_fault_page(struct vm_area_struct *vma,
				     unsigned long addr, bool do_reserve)
{
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_encl_page *entry;

	/* If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (!encl)
		return ERR_PTR(-EFAULT);
	do {
		mutex_lock(&encl->lock);
		entry = sgx_try_fault_page(vma, addr, do_reserve);
		mutex_unlock(&encl->lock);
		if (!do_reserve)
			break;
	} while (PTR_ERR(entry) == -EBUSY);

	return entry;
}
