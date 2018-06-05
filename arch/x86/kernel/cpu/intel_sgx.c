// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
// Suresh Siddha <suresh.b.siddha@intel.com>
// Serge Ayoun <serge.ayoun@intel.com>
// Shay Katz-zamir <shay.katz-zamir@intel.com>
// Sean Christopherson <sean.j.christopherson@intel.com>

#include <asm/sgx.h>
#include <asm/sgx_pr.h>
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>

#define SGX_NR_TO_SCAN	16
#define SGX_NR_LOW_PAGES 32
#define SGX_NR_HIGH_PAGES 64

bool sgx_enabled __ro_after_init = false;
EXPORT_SYMBOL(sgx_enabled);
bool sgx_lc_enabled __ro_after_init;
EXPORT_SYMBOL(sgx_lc_enabled);
atomic_t sgx_nr_free_pages = ATOMIC_INIT(0);
EXPORT_SYMBOL(sgx_nr_free_pages);
struct sgx_epc_bank sgx_epc_banks[SGX_MAX_EPC_BANKS];
EXPORT_SYMBOL(sgx_epc_banks);
int sgx_nr_epc_banks;
EXPORT_SYMBOL(sgx_nr_epc_banks);
LIST_HEAD(sgx_active_page_list);
EXPORT_SYMBOL(sgx_active_page_list);
DEFINE_SPINLOCK(sgx_active_page_list_lock);
EXPORT_SYMBOL(sgx_active_page_list_lock);

static struct task_struct *ksgxswapd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(ksgxswapd_waitq);

/*
 * Writing the LE hash MSRs is extraordinarily expensive, e.g.
 * 3-4x slower than normal MSRs, so we use a per-cpu cache to
 * track the last known value of the MSRs to avoid unnecessarily
 * writing the MSRs with the current value.  Because most Linux
 * kernels will use an LE that is signed with a non-Intel key,
 * i.e. the first EINIT will need to write the MSRs regardless
 * of the cache, the cache is intentionally left uninitialized
 * during boot as initializing the cache would be pure overhead
 * for the majority of systems.  Furthermore, the MSRs are per-cpu
 * and the boot-time values aren't guaranteed to be identical
 * across cpus, so we'd have to run code all all cpus to properly
 * init the cache.  All in all, the complexity and overhead of
 * initializing the cache is not justified.
 */
static DEFINE_PER_CPU(u64 [4], sgx_le_pubkey_hash_cache);

static void sgx_swap_cluster(void)
{
	struct sgx_epc_page *cluster[SGX_NR_TO_SCAN + 1];
	struct sgx_epc_page *epc_page;
	int i;
	int j;

	memset(cluster, 0, sizeof(cluster));

	for (i = 0, j = 0; i < SGX_NR_TO_SCAN; i++) {
		spin_lock(&sgx_active_page_list_lock);
		if (list_empty(&sgx_active_page_list)) {
			spin_unlock(&sgx_active_page_list_lock);
			break;
		}
		epc_page = list_first_entry(&sgx_active_page_list,
					    struct sgx_epc_page, list);
		if (!epc_page->impl->ops->get(epc_page)) {
			list_move_tail(&epc_page->list, &sgx_active_page_list);
			spin_unlock(&sgx_active_page_list_lock);
			continue;
		}
		list_del(&epc_page->list);
		spin_unlock(&sgx_active_page_list_lock);

		if (epc_page->impl->ops->reclaim(epc_page)) {
			cluster[j++] = epc_page;
		} else {
			spin_lock(&sgx_active_page_list_lock);
			list_add_tail(&epc_page->list, &sgx_active_page_list);
			spin_unlock(&sgx_active_page_list_lock);
			epc_page->impl->ops->put(epc_page);
		}
	}

	for (i = 0; cluster[i]; i++) {
		epc_page = cluster[i];
		epc_page->impl->ops->block(epc_page);
	}

	for (i = 0; cluster[i]; i++) {
		epc_page = cluster[i];
		epc_page->impl->ops->write(epc_page);
		epc_page->impl->ops->put(epc_page);
		sgx_free_page(epc_page);
	}
}

static int ksgxswapd(void *p)
{
	set_freezable();

	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		wait_event_freezable(ksgxswapd_waitq, kthread_should_stop() ||
				     atomic_read(&sgx_nr_free_pages) <
				     SGX_NR_HIGH_PAGES);

		if (atomic_read(&sgx_nr_free_pages) < SGX_NR_HIGH_PAGES)
			sgx_swap_cluster();
	}

	pr_info("%s: done\n", __func__);
	return 0;
}

/**
 * sgx_try_alloc_page - try to allocate an EPC page
 * @impl:	implementation for the struct sgx_epc_page
 *
 * Try to grab a page from the free EPC page list. If there is a free page
 * available, it is returned to the caller.
 *
 * Return:
 *   a &struct sgx_epc_page instace,
 *   NULL otherwise
 */
struct sgx_epc_page *sgx_try_alloc_page(struct sgx_epc_page_impl *impl)
{
	struct sgx_epc_bank *bank;
	struct sgx_epc_page *page = NULL;
	int i;

	for (i = 0; i < sgx_nr_epc_banks; i++) {
		bank = &sgx_epc_banks[i];

		down_write(&bank->lock);

		if (atomic_read(&bank->free_cnt))
			page = bank->pages[atomic_dec_return(&bank->free_cnt)];

		up_write(&bank->lock);

		if (page)
			break;
	}

	if (page) {
		atomic_dec(&sgx_nr_free_pages);
		page->impl = impl;
	}

	return page;
}
EXPORT_SYMBOL(sgx_try_alloc_page);

/**
 * sgx_alloc_page - allocate an EPC page
 * @flags:	allocation flags
 * @impl:	implementation for the struct sgx_epc_page
 *
 * Try to grab a page from the free EPC page list. If there is a free page
 * available, it is returned to the caller. If called with SGX_ALLOC_ATOMIC,
 * the function will return immediately if the list is empty. Otherwise, it
 * will swap pages up until there is a free page available. Upon returning the
 * low watermark is checked and ksgxswapd is waken up if we are below it.
 *
 * Return:
 *   a &struct sgx_epc_page instace,
 *   -ENOMEM if all pages are unreclaimable,
 *   -EBUSY when called with SGX_ALLOC_ATOMIC and out of free pages
 */
struct sgx_epc_page *sgx_alloc_page(struct sgx_epc_page_impl *impl,
				    unsigned int flags)
{
	struct sgx_epc_page *entry;

	for ( ; ; ) {
		entry = sgx_try_alloc_page(impl);
		if (entry)
			break;

		if (list_empty(&sgx_active_page_list))
			return ERR_PTR(-ENOMEM);

		if (flags & SGX_ALLOC_ATOMIC) {
			entry = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current)) {
			entry = ERR_PTR(-ERESTARTSYS);
			break;
		}

		sgx_swap_cluster();
		schedule();
	}

	if (atomic_read(&sgx_nr_free_pages) < SGX_NR_LOW_PAGES)
		wake_up(&ksgxswapd_waitq);

	return entry;
}
EXPORT_SYMBOL(sgx_alloc_page);

/**
 * sgx_free_page - free an EPC page
 *
 * @page:	any EPC page
 *
 * Remove an EPC page and insert it back to the list of free pages.
 *
 * Return: SGX error code
 */
int sgx_free_page(struct sgx_epc_page *page)
{
	struct sgx_epc_bank *bank = SGX_EPC_BANK(page);
	int ret;

	ret = sgx_eremove(page);
	if (ret) {
		pr_debug("EREMOVE returned %d\n", ret);
		return ret;
	}

	down_read(&bank->lock);
	bank->pages[atomic_inc_return(&bank->free_cnt) - 1] = page;
	atomic_inc(&sgx_nr_free_pages);
	up_read(&bank->lock);

	return 0;
}
EXPORT_SYMBOL(sgx_free_page);

/**
 * sgx_get_page - pin an EPC page
 * @page:	an EPC page
 *
 * Return: a pointer to the pinned EPC page
 */
void *sgx_get_page(struct sgx_epc_page *page)
{
	struct sgx_epc_bank *bank = SGX_EPC_BANK(page);

	if (IS_ENABLED(CONFIG_X86_64))
		return (void *)(bank->va + SGX_EPC_ADDR(page) - bank->pa);

	return kmap_atomic_pfn(SGX_EPC_PFN(page));
}
EXPORT_SYMBOL(sgx_get_page);

/**
 * sgx_put_page - unpin an EPC page
 * @ptr:	a pointer to the pinned EPC page
 */
void sgx_put_page(void *ptr)
{
	if (IS_ENABLED(CONFIG_X86_64))
		return;

	kunmap_atomic(ptr);
}
EXPORT_SYMBOL(sgx_put_page);

struct page *sgx_get_backing(struct file *file, pgoff_t index)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct address_space *mapping = inode->i_mapping;
	gfp_t gfpmask = mapping_gfp_mask(mapping);

	return shmem_read_mapping_page_gfp(mapping, index, gfpmask);
}
EXPORT_SYMBOL(sgx_get_backing);

void sgx_put_backing(struct page *backing_page, bool write)
{
	if (write)
		set_page_dirty(backing_page);

	put_page(backing_page);
}
EXPORT_SYMBOL(sgx_put_backing);

int sgx_paging_fn(struct sgx_epc_page *epc_page, struct sgx_epc_page *va_page,
		  unsigned long va_offset, struct sgx_epc_page *secs_page,
		  struct file *backing_file, struct file *pcmd_file,
		  pgoff_t index, unsigned long *addr, bool write,
		  int (*fn)(struct sgx_pageinfo *pginfo, void *epc, void *va))
{
	struct sgx_pageinfo pginfo;
	struct page *backing, *pcmd;
	unsigned long pcmd_offset;
	void *secs, *epc, *va;
	int ret;

	BUILD_BUG_ON(sizeof(struct sgx_pcmd) != 128);
	pcmd_offset = (index & 0x1f) * 128;

	backing = sgx_get_backing(backing_file, index);
	if (IS_ERR(backing))
		return PTR_ERR(backing);

	pcmd = sgx_get_backing(pcmd_file, index >> 5);
	if (IS_ERR(pcmd)) {
		ret = PTR_ERR(pcmd);
		goto out;
	}

	secs = secs_page ? sgx_get_page(secs_page) : NULL;
	epc = sgx_get_page(epc_page);
	va = sgx_get_page(va_page);

	pginfo.srcpge = (unsigned long)kmap_atomic(backing);
	pginfo.pcmd = (unsigned long)kmap_atomic(pcmd) + pcmd_offset;
	pginfo.linaddr = addr ? *addr : 0;
	pginfo.secs = (unsigned long)secs;

	ret = fn(&pginfo, epc, va + va_offset);
	if (!ret && write && addr)
		*addr = pginfo.linaddr;

	kunmap_atomic((void *)(unsigned long)(pginfo.pcmd - pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.srcpge);

	sgx_put_page(va);
	sgx_put_page(epc);
	if (secs)
		sgx_put_page(secs);

	sgx_put_backing(pcmd, !ret && write);
out:
	sgx_put_backing(backing, !ret && write);

	return ret;
}
EXPORT_SYMBOL(sgx_paging_fn);

/**
 * sgx_einit - EINIT an enclave with the appropriate LE pubkey hash
 * @sigstruct:		a pointer to the enclave's sigstruct
 * @token:		a pointer to the enclave's EINIT token
 * @secs_page:		a pointer to the enclave's SECS EPC page
 * @le_pubkey_hash:	the desired LE pubkey hash for EINIT
 */
int sgx_einit(struct sgx_sigstruct *sigstruct, struct sgx_einittoken *token,
	      struct sgx_epc_page *secs_page, u64 le_pubkey_hash[4])
{
	u64 __percpu *cache;
	void *secs;
	int i, ret;

	secs = sgx_get_page(secs_page);

	if (!sgx_lc_enabled) {
		ret = __einit(sigstruct, token, secs);
		goto out;
	}

	cache = per_cpu(sgx_le_pubkey_hash_cache, smp_processor_id());

	preempt_disable();
	for (i = 0; i < 4; i++) {
		if (le_pubkey_hash[i] == cache[i])
			continue;

		wrmsrl(MSR_IA32_SGXLEPUBKEYHASH0 + i, le_pubkey_hash[i]);
		cache[i] = le_pubkey_hash[i];
	}
	ret = __einit(sigstruct, token, secs);
	preempt_enable();

out:
	sgx_put_page(secs);
	return ret;
}
EXPORT_SYMBOL(sgx_einit);

static __init int sgx_init_epc_bank(unsigned long addr, unsigned long size,
				    unsigned long index,
				    struct sgx_epc_bank *bank)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned long i;
	void *va;

	if (IS_ENABLED(CONFIG_X86_64)) {
		va = ioremap_cache(addr, size);
		if (!va)
			return -ENOMEM;
	}

	bank->pages_data = kzalloc(nr_pages * sizeof(struct sgx_epc_page),
				   GFP_KERNEL);
	if (!bank->pages_data) {
		if (IS_ENABLED(CONFIG_X86_64))
			iounmap(va);

		return -ENOMEM;
	}

	bank->pages = kzalloc(nr_pages * sizeof(struct sgx_epc_page *),
			      GFP_KERNEL);
	if (!bank->pages) {
		if (IS_ENABLED(CONFIG_X86_64))
			iounmap(va);
		kfree(bank->pages_data);
		bank->pages_data = NULL;
		return -ENOMEM;
	}

	for (i = 0; i < nr_pages; i++) {
		bank->pages[i] = &bank->pages_data[i];
		bank->pages[i]->desc = (addr + (i << PAGE_SHIFT)) | index;
	}

	bank->pa = addr;
	bank->size = size;
	if (IS_ENABLED(CONFIG_X86_64))
		bank->va = (unsigned long)va;

	atomic_set(&bank->free_cnt, nr_pages);
	init_rwsem(&bank->lock);
	atomic_add(nr_pages, &sgx_nr_free_pages);
	return 0;
}

static __init void sgx_page_cache_teardown(void)
{
	struct sgx_epc_bank *bank;
	int i;

	for (i = 0; i < sgx_nr_epc_banks; i++) {
		bank = &sgx_epc_banks[i];

		if (IS_ENABLED(CONFIG_X86_64))
			iounmap((void *)bank->va);

		kfree(bank->pages);
		kfree(bank->pages_data);
	}

	if (ksgxswapd_tsk) {
		kthread_stop(ksgxswapd_tsk);
		ksgxswapd_tsk = NULL;
	}
}

static __init int sgx_page_cache_init(void)
{
	struct task_struct *tsk;
	unsigned long size;
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	unsigned long pa;
	int i;
	int ret;

	for (i = 0; i < SGX_MAX_EPC_BANKS; i++) {
		cpuid_count(SGX_CPUID, i + SGX_CPUID_EPC_BANKS, &eax, &ebx,
			    &ecx, &edx);
		if (!(eax & 0xf))
			break;

		pa = ((u64)(ebx & 0xfffff) << 32) + (u64)(eax & 0xfffff000);
		size = ((u64)(edx & 0xfffff) << 32) + (u64)(ecx & 0xfffff000);

		pr_info("EPC bank 0x%lx-0x%lx\n", pa, pa + size);

		ret = sgx_init_epc_bank(pa, size, i, &sgx_epc_banks[i]);
		if (ret) {
			sgx_page_cache_teardown();
			return ret;
		}

		sgx_nr_epc_banks++;
	}

	tsk = kthread_run(ksgxswapd, NULL, "ksgxswapd");
	if (IS_ERR(tsk)) {
		sgx_page_cache_teardown();
		return PTR_ERR(tsk);
	}
	ksgxswapd_tsk = tsk;
	return 0;
}

static __init bool sgx_is_enabled(bool *lc_enabled)
{
	unsigned long fc;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		return false;

	if (!boot_cpu_has(X86_FEATURE_SGX))
		return false;

	if (!boot_cpu_has(X86_FEATURE_SGX1))
		return false;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, fc);
	if (!(fc & FEATURE_CONTROL_LOCKED))
		return false;

	if (!(fc & FEATURE_CONTROL_SGX_ENABLE))
		return false;

	*lc_enabled = !!(fc & FEATURE_CONTROL_SGX_LE_WR);

	return true;
}

static __init int sgx_init(void)
{
	bool lc_enabled;
	int ret;

	if (!sgx_is_enabled(&lc_enabled))
		return 0;

	ret = sgx_page_cache_init();
	if (ret)
		return ret;

	sgx_enabled = true;
	sgx_lc_enabled = lc_enabled;

	return 0;
}

arch_initcall(sgx_init);
