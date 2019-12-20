// SPDX-License-Identifier: GPL-2.0

#include <linux/miscdevice.h>
#include <linux/kvm_host.h>
#include <linux/kvm_types.h>
#include <linux/mm.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <asm/delay.h>
#include <asm/sgx.h>
#include <uapi/asm/sgx.h>

#include "encl.h"
#include "enclx.h"
#include "sgx.h"
#include "virt.h"

struct sgx_virt_epc {
	struct radix_tree_root page_tree;
	struct rw_semaphore lock;

	struct kref kref;

	struct kvm *kvm;
	struct mm_struct *mm;
	struct file *backing;
	struct list_head va_pages;

	gfn_to_hva_fn_t *gfn_to_hva;
	unsigned long swap_size;

	bool dead;
};

struct sgx_virt_epc_page {
	struct sgx_virt_epc *epc;
	// union {
		struct sgx_epc_page *epc_page;
		struct sgx_va_page *va_page;
	// };

	// union {
		/*
		 * Host virtual address of the page, valid when the page is
		 * resident in the host page tables, and thus the EPC.
		 */
		unsigned long hva;

		/*
		 * Enclave virtual (linear) address, valid when the page has
		 * been evicted from the EPC.
		 */
		unsigned long enclave_address;
	// }
	unsigned long secs_hva;
	unsigned int va_offset;

	bool invalid;
	bool present;
	bool pinned;
	bool zapped;
	bool evicted;
	bool guest_blocked;
	bool host_tracked;
	bool host_locked;
	bool is_secs;
	bool is_child;
};

static struct mutex virt_epc_lock;
static struct list_head virt_epc_zombie_pages;

static struct sgx_virt_epc_page*
sgx_virt_epc_pin_secs(struct sgx_virt_epc *child_epc, unsigned long secs_hva);

static void sgx_virt_epc_unpin_secs(struct sgx_virt_epc *child_epc,
				    struct sgx_virt_epc_page *secs_page);

static int sgx_virt_epc_reload_page(struct sgx_virt_epc *epc,
				    struct sgx_virt_epc_page *page,
				    struct sgx_virt_epc_page *secs,
				    struct sgx_epc_page *epc_page,
				    unsigned long addr);

static inline bool sgx_virt_epc_reclaim_enabled(struct sgx_virt_epc *epc)
{
	return !!epc->kvm;
}

static inline unsigned long sgx_virt_epc_calc_index(struct vm_area_struct *vma,
						    unsigned long addr)
{
	return vma->vm_pgoff + PFN_DOWN(addr - vma->vm_start);
}

static int __sgx_virt_epc_fault(struct vm_area_struct *vma, unsigned long addr)
{
	struct sgx_virt_epc *epc = vma->vm_private_data;
	struct sgx_virt_epc_page *page;
	struct sgx_virt_epc_page *secs;
	struct sgx_epc_page *epc_page;
	unsigned long index;
	int ret;

	if (WARN_ON(addr & ~PAGE_MASK))
		return -EFAULT;

	/*
	 * For simplicity (ha!), do not allow creating PTEs across different mm
	 * structs once reclaim is enabled.  Note, pre-faulting before enabling
	 * reclaim is impossible as attempting to enable reclaim after the EPC
	 * has been mmap()'d will fail.
	 */
	if (sgx_virt_epc_reclaim_enabled(epc) && epc->mm != vma->vm_mm)
		return -EFAULT;

	if (epc->dead)
		return -EFAULT;

	secs = NULL;
	index = sgx_virt_epc_calc_index(vma, addr);
	page = radix_tree_lookup(&epc->page_tree, index);
	if (page) {
		if (page->zapped)
			return -EBUSY;
		if (page->present)
			return 0;

		epc_page = page->epc_page;

		/*
		 * A !PRESENT && !EVICTED page can be encountered if a past
		 * vmf_insert_pfn() failed, either after ELD* a page during a
		 * fault or after zapping an SECS that couldn't be evicted
		 * because the SECS had child pages.
		 */
		if (!page->evicted && epc_page) {
			ret = vmf_insert_pfn(vma, addr, sgx_epc_pfn(epc_page));
			if (likely(ret == VM_FAULT_NOPAGE))
				goto out;
			else
				return -EFAULT;
		}
	} else {
		page = kzalloc(sizeof(*page), GFP_KERNEL);
		if (!page)
			return -ENOMEM;

		page->epc = epc;

		ret = radix_tree_insert(&epc->page_tree, index, page);
		if (unlikely(ret)) {
			kfree(page);
			return ret;
		}
	}

	if (page->evicted && page->is_child) {
		secs = sgx_virt_epc_pin_secs(epc, page->secs_hva);
		if (IS_ERR(secs))
			return PTR_ERR(secs);
	}

	epc_page = sgx_alloc_page(&epc, false);
	if (IS_ERR(epc_page))
		return PTR_ERR(epc_page);

	/*
	 * Load the page into the EPC first, else the guest will see a #PF with
	 * PFEC.SGX=1 and think the EPC has been invalidated.
	 */
	if (page->evicted) {
		ret = sgx_virt_epc_reload_page(epc, page, secs, epc_page, addr);
		if (ret) {
			sgx_free_page(epc_page);
			if (secs)
				sgx_virt_epc_unpin_secs(epc, secs);
			return ret;
		}
	}

	epc_page->owner = page;

	/*
	 * Don't free the EPC page even if vmf_insert_pfn() fails, the page is
	 * still !PRESENT and can be handled by retrying vmf_insert_pfn() if
	 * userspace restarts the guest and retries the fault.
	 */
	page->epc_page = epc_page;

	ret = vmf_insert_pfn(vma, addr, sgx_epc_pfn(epc_page));
	if (unlikely(ret != VM_FAULT_NOPAGE))
		return -EFAULT;

out:
	page->hva = addr;
	page->present = true;

	if (sgx_virt_epc_reclaim_enabled(epc))
		sgx_mark_page_reclaimable(epc_page, SGX_EPC_PAGE_GUEST);

	/*
	 * Don't unpin the SECS until the bitter end, doing so may drop the
	 * lock for the child's EPC.
	 */
	if (secs)
		sgx_virt_epc_unpin_secs(epc, secs);

	return 0;
}

static vm_fault_t sgx_virt_epc_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct sgx_virt_epc *epc = vma->vm_private_data;
	int ret;

retry:
	down_write(&epc->lock);
	ret = __sgx_virt_epc_fault(vma, vmf->address);
	up_write(&epc->lock);

	if (!ret || signal_pending(current))
		return VM_FAULT_NOPAGE;

	if (ret == -EBUSY) {
		up_read(&vma->vm_mm->mmap_sem);

		sgx_reclaim_pages();

		if (down_read_killable(&vma->vm_mm->mmap_sem))
			return VM_FAULT_SIGBUS;
		goto retry;
	}

	return VM_FAULT_SIGBUS;
}

static int sgx_virt_epc_access(struct vm_area_struct *vma, unsigned long start,
			       void *buf, int len, int write)
{
	/* EDBG{RD,WR} are naturally sized, i.e. always 8-byte on 64-bit. */
	unsigned char data[sizeof(unsigned long)];
	struct sgx_virt_epc_page *page;
	struct sgx_virt_epc *epc;
	unsigned long addr, index;
	int offset, cnt, i;
	int ret = 0;
	void *p;

	epc = vma->vm_private_data;

	for (i = 0; i < len && !ret; i += cnt) {
		addr = start + i;
		if (i == 0 || PFN_DOWN(addr) != PFN_DOWN(addr - cnt))
			index = sgx_virt_epc_calc_index(vma, addr);

		down_read(&epc->lock);
		page = radix_tree_lookup(&epc->page_tree, index);
		if (!page || !page->epc_page)
			page = ERR_PTR(-EFAULT);
		up_read(&epc->lock);

		/*
		 * EDBG{RD,WR} require an active enclave, and given that virt
		 * EPC doesn't support reclaim, a !PRESENT EPC page means the
		 * guest hasn't accessed the page and therefore can't
		 * possibility have added the page to an enclave.
		 */
		if (IS_ERR(page))
			return PTR_ERR(page);

		offset = addr & (sizeof(unsigned long) - 1);
		addr = ALIGN_DOWN(addr, sizeof(unsigned long));
		cnt = min((int)sizeof(unsigned long) - offset, len - i);

		p = sgx_epc_addr(page->epc_page) + (addr & ~PAGE_MASK);

		/* EDBGRD for read, or to do RMW for a partial write. */
		if (!write || cnt != sizeof(unsigned long))
			ret = __edbgrd(p, (void *)data);

		if (!ret) {
			if (write) {
				memcpy(data + offset, buf + i, cnt);
				ret = __edbgwr(p, (void *)data);
			} else {
				memcpy(buf + i, data + offset, cnt);
			}
		}
	}

	if (ret)
		return -EIO;
	return i;
}

const struct vm_operations_struct sgx_virt_epc_vm_ops = {
	.fault = sgx_virt_epc_fault,
	.access = sgx_virt_epc_access,
};

static void sgx_virt_epc_free_va_pages(struct sgx_virt_epc *epc)
{
	struct sgx_va_page *va_page, *tmp;

	if (list_empty(&epc->va_pages))
		return;

	/*
	 * The reclaimer is responsible for checking epc->dead before doing
	 * EWB, thus it's safe to free VA pages even if the reclaimer holds a
	 * reference to the virtual EPC.
	 */
	list_for_each_entry_safe(va_page, tmp, &epc->va_pages, list) {
		list_del(&va_page->list);
		sgx_free_page(va_page->epc_page);
		kfree(va_page);
	}
}

static int sgx_virt_epc_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct sgx_virt_epc *epc = file->private_data;
	unsigned long swap_size, nr_pages, i;
	struct sgx_va_page *va_page;
	struct file *backing;
	int ret;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	if (down_write_killable(&epc->lock))
		return -EINTR;

	/* Don't allow multiple mmap() calls when reclaim is enabled. */
	if (sgx_virt_epc_reclaim_enabled(epc) && epc->swap_size) {
		ret = -EEXIST;
		goto out_unlock;
	}

	/*
	 * Calc the swap size even if reclaim isn't enabled so that it *can't*
	 * be enabled after any part of the virtual EPC has been mapped.
	 */
	nr_pages = sgx_virt_epc_calc_index(vma, vma->vm_end);
	swap_size = nr_pages << PAGE_SHIFT;

	if (!sgx_virt_epc_reclaim_enabled(epc))
		goto no_reclaim;

	backing = shmem_file_setup("sgx_virt_epc_backing",
				   swap_size + (swap_size >> 5), VM_NORESERVE);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		goto out_unlock;
	}

	for (i = 0; i < nr_pages; i+= SGX_VA_SLOT_COUNT) {
		va_page = kzalloc(sizeof(*va_page), GFP_KERNEL);
		if (!va_page) {
			ret = -ENOMEM;
			goto out_free;
		}

		va_page->epc_page = sgx_alloc_va_page();
		if (IS_ERR(va_page->epc_page)) {
			ret = PTR_ERR(va_page->epc_page);
			kfree(va_page);
			goto out_free;
		}
		list_add(&va_page->list, &epc->va_pages);
	}

	epc->backing = backing;

no_reclaim:
	epc->swap_size = nr_pages << PAGE_SHIFT;
	up_write(&epc->lock);

	vma->vm_ops = &sgx_virt_epc_vm_ops;
	vma->vm_flags |= VM_PFNMAP | VM_IO | VM_DONTDUMP;
	vma->vm_private_data = file->private_data;

	return 0;

out_free:
	sgx_virt_epc_free_va_pages(epc);
	fput(backing);
out_unlock:
	up_write(&epc->lock);

	return ret;
}

static int sgx_virt_epc_free_page(struct sgx_epc_page *epc_page)
{
	int ret, i = 0;

	if (!epc_page)
		return 0;

	do {
		ret = sgx_unmark_page_reclaimable(epc_page);
	} while (ret == -EBUSY && ++i < 100);
	if (WARN_ON_ONCE(ret))
		return ret;

	ret = __eremove(sgx_epc_addr(epc_page));
	if (ret) {
		WARN_ON(ret != SGX_CHILD_PRESENT);
		return ret;
	}

	__sgx_free_page(epc_page);
	return 0;
}

static void __sgx_virt_epc_release(struct kref *ref)
{
	struct sgx_virt_epc *epc = container_of(ref, struct sgx_virt_epc, kref);
	struct sgx_epc_page *epc_page, *tmp;
	struct sgx_virt_epc_page *page;
	struct radix_tree_iter iter;
	void **slot;

	LIST_HEAD(secs_pages);

	WARN_ON_ONCE(!list_empty(&epc->va_pages));

	if (epc->mm)
		mmdrop(epc->mm);

	if (epc->backing)
		fput(epc->backing);

	radix_tree_for_each_slot(slot, &epc->page_tree, &iter, 0) {
		page = *slot;
		if (sgx_virt_epc_free_page(page->epc_page))
			continue;

		kfree(page);
		radix_tree_delete(&epc->page_tree, iter.index);
	}

	/*
	 * Because we don't track which pages are SECS pages, it's possible
	 * for EREMOVE to fail, e.g. a SECS page can have children if a VM
	 * shutdown unexpectedly.  Retry all failed pages after iterating
	 * through the entire tree, at which point all children should be
	 * removed and the SECS pages can be nuked as well...unless userspace
	 * has exposed multiple instance of virtual EPC to a single VM.
	 */
	radix_tree_for_each_slot(slot, &epc->page_tree, &iter, 0) {
		page = *slot;
		if (sgx_virt_epc_free_page(page->epc_page))
			list_add_tail(&page->epc_page->list, &secs_pages);

		kfree(page);
		radix_tree_delete(&epc->page_tree, iter.index);
	}

	/*
	 * Third time's a charm.  Try to EREMOVE zombie SECS pages from virtual
	 * EPC instances that were previously released, i.e. free SECS pages
	 * that were in limbo due to having children in *this* EPC instance.
	 */
	mutex_lock(&virt_epc_lock);
	list_for_each_entry_safe(epc_page, tmp, &virt_epc_zombie_pages, list) {
		/*
		 * Speculatively remove the page from the list of zombies, if
		 * the page is successfully EREMOVE it will be added to the
		 * list of free pages.  If EREMOVE fails, throw the page on the
		 * local list, which will be spliced on at the end.
		 */
		list_del(&epc_page->list);

		if (sgx_virt_epc_free_page(epc_page))
			list_add_tail(&epc_page->list, &secs_pages);
	}

	if (!list_empty(&secs_pages))
		list_splice_tail(&secs_pages, &virt_epc_zombie_pages);
	mutex_unlock(&virt_epc_lock);

	kfree(epc);
}

static int sgx_virt_epc_release(struct inode *inode, struct file *file)
{
	struct sgx_virt_epc *epc = file->private_data;

	kref_put(&epc->kref, __sgx_virt_epc_release);
	return 0;
}

static int sgx_virt_epc_open(struct inode *inode, struct file *file)
{
	struct sgx_virt_epc *epc;

	epc = kzalloc(sizeof(struct sgx_virt_epc), GFP_KERNEL);
	if (!epc)
		return -ENOMEM;

	init_rwsem(&epc->lock);
	INIT_RADIX_TREE(&epc->page_tree, GFP_KERNEL);
	INIT_LIST_HEAD(&epc->va_pages);
	kref_init(&epc->kref);

	file->private_data = epc;

	return 0;
}

const struct file_operations sgx_virt_epc_fops = {
	.owner			= THIS_MODULE,
	.open			= sgx_virt_epc_open,
	.release		= sgx_virt_epc_release,
	.mmap			= sgx_virt_epc_mmap,
};

static struct miscdevice sgx_virt_epc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "virt_epc",
	.nodename = "sgx/virt_epc",
	.fops = &sgx_virt_epc_fops,
};

int __init sgx_virt_epc_init(void)
{
	INIT_LIST_HEAD(&virt_epc_zombie_pages);
	mutex_init(&virt_epc_lock);

	return misc_register(&sgx_virt_epc_dev);
}

int sgx_virt_ecreate(struct sgx_pageinfo *pageinfo, void __user *secs,
		     int *trapnr)
{
	int ret;

	__uaccess_begin();
	ret = __ecreate(pageinfo, (void *)secs);
	__uaccess_end();

	if (enclx_faulted(ret)) {
		*trapnr = ENCLx_TRAPNR(ret);
		return -EFAULT;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(sgx_virt_ecreate);

static int __sgx_virt_einit(void __user *sigstruct, void __user *token,
			    void __user *secs)
{
	int ret;

	__uaccess_begin();
	ret =  __einit((void *)sigstruct, (void *)token, (void *)secs);
	__uaccess_end();
	return ret;
}

int sgx_virt_einit(void __user *sigstruct, void __user *token,
		   void __user *secs, u64 *lepubkeyhash, int *trapnr)
{
	int ret;

	if (!boot_cpu_has(X86_FEATURE_SGX_LC)) {
		ret = __sgx_virt_einit(sigstruct, token, secs);
	} else {
		preempt_disable();
		sgx_update_lepubkeyhash_msrs(lepubkeyhash, false);
		ret = __sgx_virt_einit(sigstruct, token, secs);
		if (ret == SGX_INVALID_EINITTOKEN) {
			sgx_update_lepubkeyhash_msrs(lepubkeyhash, true);
			ret = __sgx_virt_einit(sigstruct, token, secs);
		}
		preempt_enable();
	}

	if (enclx_faulted(ret)) {
		*trapnr = ENCLx_TRAPNR(ret);
		return -EFAULT;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(sgx_virt_einit);

void *sgx_virt_enable_reclaim(int epc_fd, struct kvm *kvm,
			      gfn_to_hva_fn_t *fn)
{
	struct sgx_virt_epc *epc;
	struct file *epc_file;
	void *ret;

	epc_file = fget(epc_fd);
	if (!epc_file)
		return ERR_PTR(-EINVAL);

	if (epc_file->f_op != &sgx_virt_epc_fops) {
		ret = ERR_PTR(-EINVAL);
		goto out;
	}

	epc = epc_file->private_data;

	if (down_write_killable(&epc->lock)) {
		ret = ERR_PTR(-EINTR);
		goto out;
	}

	if (sgx_virt_epc_reclaim_enabled(epc) || epc->swap_size) {
		ret = ERR_PTR(-EEXIST);
		goto out_unlock;
	}
	if (epc->dead) {
		ret = ERR_PTR(-EFAULT);
		goto out_unlock;
	}

	/*
	 * Grab a refcount to kvm->mm to allow down_read(mm->mmap_sem) after
	 * KVM dies.  mmap_sem needs to be taken before epc->lock, and epc->kvm
	 * can't be reliably checked until epc->lock is held.
	 */
	epc->mm = kvm->mm;
	mmgrab(epc->mm);

	epc->kvm = kvm;
	epc->gfn_to_hva = fn;

	kref_get(&epc->kref);

	ret = epc;
out_unlock:
	up_write(&epc->lock);
out:
	fput(epc_file);

	return ret;
}
EXPORT_SYMBOL_GPL(sgx_virt_enable_reclaim);

void sgx_virt_disable_reclaim(void *virt_epc)
{
	struct sgx_virt_epc *epc = virt_epc;

	if (WARN_ON_ONCE(!sgx_virt_epc_reclaim_enabled(epc)))
		return;

	down_write(&epc->lock);

	epc->dead = true;
	epc->kvm = NULL;
	epc->gfn_to_hva = NULL;

	sgx_virt_epc_free_va_pages(epc);

	up_write(&epc->lock);

	kref_put(&epc->kref, __sgx_virt_epc_release);
}
EXPORT_SYMBOL_GPL(sgx_virt_disable_reclaim);

bool sgx_virt_reclaimer_get_ref(struct sgx_epc_page *epc_page)
{
	struct sgx_virt_epc_page *page = epc_page->owner;

	if (page->epc->dead || !sgx_virt_epc_reclaim_enabled(page->epc))
		return false;

	return kref_get_unless_zero(&page->epc->kref);
}

void sgx_virt_reclaimer_put_ref(struct sgx_epc_page *epc_page)
{
	struct sgx_virt_epc_page *page = epc_page->owner;

	kref_put(&page->epc->kref, __sgx_virt_epc_release);
}

bool sgx_virt_reclaimer_age(struct sgx_epc_page *epc_page)
{
	struct sgx_virt_epc_page *page = epc_page->owner;
	struct sgx_virt_epc *epc;
	int young;

	epc = page->epc;

	down_read(&epc->mm->mmap_sem);

	young = mmu_notifier_clear_young(epc->mm, page->hva,
					 page->hva  + PAGE_SIZE);

	up_read(&epc->mm->mmap_sem);

	return !young && !page->pinned;
}

int sgx_virt_reclaimer_get_backing(struct sgx_epc_page *epc_page,
				   struct sgx_backing *backing)
{
	struct sgx_virt_epc_page *page = epc_page->owner;
	struct sgx_virt_epc *epc = page->epc;
	struct vm_area_struct *vma;
	unsigned long index;
	int ret;

	down_read(&epc->mm->mmap_sem);
	down_read(&epc->lock);

	if (epc->dead) {
		ret = -EFAULT;
		goto out_unlock;
	}

	if (page->pinned) {
		ret = -EBUSY;
		goto out_unlock;
	}

	/* Kill the EPC if the page's VMA has been unmapped or remapped. */
	vma = find_vma_intersection(epc->mm, page->hva, page->hva + 1);
	if (!vma || vma->vm_private_data != epc) {
		ret = -EFAULT;
		epc->dead = true;
		goto out_unlock;
	}

	WARN_ON_ONCE(page->evicted || !page->present);

	index = sgx_virt_epc_calc_index(vma, page->hva);
	ret = sgx_get_backing(epc->backing, epc->swap_size, index, backing);

out_unlock:
	up_read(&epc->lock);
	up_read(&epc->mm->mmap_sem);
	return ret;
}


int sgx_virt_reclaimer_block(struct sgx_epc_page *epc_page)
{
	struct sgx_virt_epc_page *page;
	struct vm_area_struct *vma;
	struct sgx_virt_epc *epc;
	unsigned long page_type;
	unsigned long secs_hva;
	struct sgx_rdinfo info;
	int ret;

	page = epc_page->owner;
	epc = page->epc;

	if (!mmget_not_zero(epc->mm))
		return -EFAULT;

	down_read(&epc->mm->mmap_sem);
	down_write(&epc->lock);

	if (epc->dead) {
		ret = -EFAULT;
		goto out_unlock;
	}

	if (page->pinned) {
		ret = -EBUSY;
		goto out_unlock;
	}

	/* Kill the EPC if the page's VMA has been unmapped or remapped. */
	vma = find_vma_intersection(epc->mm, page->hva, page->hva + 1);
	if (!vma || vma->vm_private_data != epc)
		goto out_kill;

	/* Zap SPTEs before EDRINFO to avoid racing with the guest. */
	zap_vma_ptes(vma, page->hva, PAGE_SIZE);

	page->zapped = true;
	page->invalid = false;
	page->is_secs = false;
	page->is_child = false;
	page->guest_blocked = false;

	ret = __erdinfo(&info, sgx_epc_addr(epc_page));
	if (ret == SGX_PG_INVLD) {
		ret = 0;
		page->invalid = true;
		goto out_unlock;
	} else if (unlikely(ret)) {
		if (encls_failed(ret))
			ENCLx_WARN(ret, "ERDINFO");
		goto out_kill;
	}

	page_type = SGX_RDINFO_TO_PAGE_TYPE(info);
	if (page_type == SGX_PAGE_TYPE_SECS) {
		/*
		 * Our lone failure scenario: it's an SECS page with active
		 * children.  Clear the zapped indicator and restore its SPTE.
		 * Failure to restore the SPTE is relatively benign, we can
		 * handle it cleanly by clearing the present flag.  The fault
		 * handler has dedicated code for this scenario, so the only
		 * downside is we'll take an additional fault (or two).
		 */
		if (info.status & SGX_STATUS_CHILDPRESENT) {
			/*
			 * Mark the page !PRESENT if inserting the PFN fails so
			 * that the fault handler will retry vmf_insert_pfn().
			 */
			ret = vmf_insert_pfn(vma, page->hva, sgx_epc_pfn(epc_page));
			if (ret != VM_FAULT_NOPAGE)
				page->present = false;
			page->zapped = false;
			ret = -EBUSY;
			goto out_unlock;
		}
		page->is_secs = true;
	} else if (page_type != SGX_PAGE_TYPE_VA) {
		/*
		 * Bit 0 is set if enclavecontext contains an HVA.  See
		 * sgx_virt_epc_reload_page().
		 */
		if (info.enclavecontext & 1) {
			secs_hva = info.enclavecontext & PAGE_MASK;
		} else {
			secs_hva = epc->gfn_to_hva(epc->kvm,
						   PFN_DOWN(info.enclavecontext));
			if (kvm_is_error_hva(secs_hva))
				goto out_kill;
		}

		page->secs_hva = secs_hva;
		page->is_child = true;

		/*
		 * Proceed with eviction even if the page is already BLOCKED,
		 * i.e. is about to be evicted by the guest.  Not evicting the
		 * page would allow a buggy or malicious guest to DoS the host
		 * by not freeing up EPC.
		 */
		if (info.flags & SGX_RDINFO_BLOCKED)
			page->guest_blocked = true;
		else if (WARN_ON_ONCE(__eblock(sgx_epc_addr(epc_page)))) 
			goto out_kill;
	}
	ret = 0;

out_unlock:
	up_write(&epc->lock);
	up_read(&epc->mm->mmap_sem);
	mmput(epc->mm);
	return ret;

out_kill:
	ret = -EFAULT;
	epc->dead = true;
	goto out_unlock;
}

static void sgx_ipi_cb(void *info)
{

}

static int sgx_virt_epc_track(struct sgx_virt_epc *epc,
			      struct sgx_virt_epc_page *secs_page)
{
	void *secs;
	int i, ret;

	if (WARN_ON_ONCE(!secs_page))
		return -EFAULT;

	secs_page->host_locked = true;
	secs_page->host_tracked = true;

	secs = sgx_epc_addr(secs_page->epc_page);

	for (i = 0; i < 10; i++) {
		ret = __etrackc(secs);
		if (ret != SGX_EPC_PAGE_CONFLICT)
			break;
	}
	if (ret == SGX_PREV_TRK_INCMPL) {
		on_each_cpu_mask(mm_cpumask(epc->mm), sgx_ipi_cb, NULL, 1);
		ret = __etrackc(secs);
	}
	if (ret == SGX_EPC_PAGE_CONFLICT) {
		on_each_cpu_mask(mm_cpumask(epc->mm), sgx_ipi_cb, NULL, 0);

		for (i = 0; i < 10; i++) {
			ret = __etrackc(secs);
			if (ret != SGX_EPC_PAGE_CONFLICT)
				break;
		}
	}

	ENCLx_WARN(ret, "ETRACKC");
	return ret;
}

static struct sgx_virt_epc_page*
__sgx_virt_epc_pin_page(struct vm_area_struct *vma, unsigned long addr)
{
	struct sgx_virt_epc_page *page;
	struct sgx_virt_epc *epc;
	unsigned long index;
	int ret;

	ret = __sgx_virt_epc_fault(vma, addr);
	if (ret)
		return ERR_PTR(ret);

	epc = vma->vm_private_data;

	index = sgx_virt_epc_calc_index(vma, addr);
	page = radix_tree_lookup(&epc->page_tree, index);
	if (WARN_ON_ONCE(!page || !page->present))
		return ERR_PTR(-EFAULT);

	page->pinned = true;
	return page;
}

static struct sgx_virt_epc_page*
sgx_virt_epc_pin_secs(struct sgx_virt_epc *child_epc, unsigned long secs_hva)
{
	struct sgx_virt_epc_page *page;
	struct vm_area_struct *vma;
	struct sgx_virt_epc *epc;

	vma = find_vma_intersection(child_epc->mm, secs_hva, secs_hva + 1);
	if (!vma)
		return ERR_PTR(-EFAULT);

	/* Same virtual EPC. */
	if (vma->vm_private_data == child_epc)
		return __sgx_virt_epc_pin_page(vma, secs_hva);

	if (vma->vm_ops != &sgx_virt_epc_vm_ops)
		return ERR_PTR(-EFAULT);

	epc = vma->vm_private_data;

	/* Unlock the child's EPC, lock the SECS' EPC, and fault it in. */
	up_write(&child_epc->lock);

	down_write(&epc->lock);
	page = __sgx_virt_epc_pin_page(vma, secs_hva);
	up_write(&epc->lock);

	down_write(&child_epc->lock);
	return page;
}

static void sgx_virt_epc_unpin_secs(struct sgx_virt_epc *child_epc,
				    struct sgx_virt_epc_page *secs_page)
{
	/* Same virtual EPC. */
	if (secs_page->epc == child_epc) {
		secs_page->pinned = false;
	} else {
		/* Unlock the child's EPC, lock the SECS' EPC, and unpin the SECS. */
		up_write(&child_epc->lock);

		down_write(&secs_page->epc->lock);
		secs_page->pinned = false;
		up_write(&secs_page->epc->lock);

		down_write(&child_epc->lock);
	}
}

int sgx_virt_reclaimer_write(struct sgx_epc_page *epc_page,
			     struct sgx_backing *backing)
{
	struct sgx_virt_epc_page *page = epc_page->owner;
	struct sgx_virt_epc_page *secs_page;
	struct sgx_va_page *va_page;
	struct sgx_virt_epc *epc;
	unsigned int va_offset;
	void *va_slot;
	int ret;

	epc = page->epc;

	down_read(&epc->mm->mmap_sem);
	down_write(&epc->lock);

	ret = -EFAULT;
	if (epc->dead || WARN_ON(page->pinned))
		goto out_dead;

	ret = 0;
	if (page->invalid)
		goto out_invalid;

	/*
	 * Note, pinning the SECS may temporarily drop epc->lock.  The page
	 * cannot be freed as EREMOVE will fail with SGX_CHILD_PRESENT (because
	 * @page is its child), even if its virtual EPC is released.
	 */
	if (page->is_child) {
		secs_page = sgx_virt_epc_pin_secs(epc, page->secs_hva);
		if (IS_ERR(secs_page)) {
			ret = PTR_ERR(secs_page);
			goto out_dead;
		}

		ret = __eincvirtchild(sgx_epc_addr(epc_page),
				      sgx_epc_addr(secs_page->epc_page));
		if (ret) {
			if (encls_failed(ret))
				ENCLx_WARN(ret, "EINCVIRTCHILD");
			epc->dead = true;
			goto out_dead;
		}
	} else if (page->is_secs) {
		secs_page = page;
	} else {
		secs_page = NULL;
	}

	va_page = list_first_entry(&epc->va_pages, struct sgx_va_page, list);
	va_offset = sgx_alloc_va_slot(va_page);
	va_slot = sgx_epc_addr(va_page->epc_page) + va_offset;
	if (sgx_va_page_full(va_page))
		list_move_tail(&va_page->list, &epc->va_pages);

	if (WARN_ON((va_offset >> 3) == SGX_VA_SLOT_COUNT)) {
		ret = -EFAULT;
		goto ewb_done;
	}

	ret = sgx_ewb(page->epc_page, va_slot, backing, &page->enclave_address);
	if (ret != SGX_NOT_TRACKED || sgx_virt_epc_track(epc, secs_page))
		goto ewb_done;

	ret = sgx_ewb(page->epc_page, va_slot, backing, &page->enclave_address);
	if (ret != SGX_NOT_TRACKED)
		goto ewb_done;

	/*
	 * Slow path, send IPIs to kick cpus out of the enclave.  Note, it's
	 * imperative that the cpu mask is generated *after* ETRACK, else we'll
	 * miss cpus that entered the enclave between generating the mask and
	 * incrementing epoch.
	 */
	on_each_cpu_mask(mm_cpumask(epc->mm), sgx_ipi_cb, NULL, 1);
	ret = sgx_ewb(page->epc_page, va_slot, backing, &page->enclave_address);

ewb_done:
	if (unlikely(ret)) {
		if (page->is_child)
			__edecvirtchild(sgx_epc_addr(epc_page),
					sgx_epc_addr(secs_page->epc_page));
		if (encls_failed(ret))
			ENCLx_WARN(ret, "EWB");
		sgx_free_va_slot(va_page, va_offset);
		epc->dead = true;
		goto out_dead;
	}

	page->evicted = true;
	page->va_offset = va_offset;
	page->va_page = va_page;

	if (page->is_child)
		sgx_virt_epc_unpin_secs(epc, secs_page);

out_invalid:
	page->zapped = false;
	page->present = false;
	page->epc_page = NULL;

out_dead:
	up_write(&epc->lock);
	up_read(&epc->mm->mmap_sem);

	return ret;
}

static int sgx_virt_epc_reload_page(struct sgx_virt_epc *epc,
				    struct sgx_virt_epc_page *page,
				    struct sgx_virt_epc_page *secs,
				    struct sgx_epc_page *epc_page,
				    unsigned long addr)
{
	struct sgx_enclavecontext context;
	struct sgx_epc_page *secs_page;
	struct sgx_va_page *va_page;
	struct sgx_backing backing;
	struct sgx_pageinfo pginfo;
	struct vm_area_struct *vma;
	unsigned long index;
	void *va_slot;
	int ret;

	va_page = page->va_page;

	if (secs) {
		secs_page = secs->epc_page;

		/*
		 * Set the locked flag on the SECS, not the page itself.  EPCM
		 * lock conflicts between KVM and its guests can only occur on
		 * SECS pages (locks are only taken on non-SECS pages when they
		 * aren't mapped in the guest), any other page type is a
		 * conflict within the guest itself.  
		 */
		secs->host_locked = true;
	} else {
		if (page->is_secs)
			page->host_locked = true;
		secs_page = NULL;
	}

	/* Kill the EPC if the page's VMA has been unmapped or remapped. */
	vma = find_vma_intersection(epc->mm, page->hva, page->hva + 1);
	if (!vma || vma->vm_private_data != epc) {
		epc->dead = true;
		return -EFAULT;
	}

	index = sgx_virt_epc_calc_index(vma, page->hva);
	ret = sgx_get_backing(epc->backing, epc->swap_size, index, &backing);
	if (ret)
		return ret;

	pginfo.addr = page->enclave_address;
	pginfo.contents = (u64)kmap_atomic(backing.contents);
	pginfo.metadata = (u64)kmap_atomic(backing.pcmd) + backing.pcmd_offset;
	if (secs_page)
		pginfo.secs = (u64)sgx_epc_addr(secs_page);
	else
		pginfo.secs = 0;

	va_slot = sgx_epc_addr(va_page->epc_page) + page->va_offset;

retry:
	if (page->guest_blocked)
		ret = __eldbc(&pginfo, sgx_epc_addr(epc_page), va_slot);
	else
		ret = __elduc(&pginfo, sgx_epc_addr(epc_page), va_slot);

	if (ret == SGX_EPC_PAGE_CONFLICT)
		goto retry;

	sgx_put_backing(&backing, false);

	if (ret) {
		if (encls_failed(ret))
			ENCLx_WARN(ret, page->guest_blocked ? "ELDBC" : "ELDUC");
		epc->dead = true;
		return -EFAULT;
	}

	if (page->is_child) {
		__edecvirtchild(sgx_epc_addr(epc_page), sgx_epc_addr(secs_page));
	} else if (page->is_secs) {
		context.enclavecontext = addr | 1;
		__esetcontext(sgx_epc_addr(epc_page), &context);
	}
	page->evicted = false;

	sgx_free_va_slot(va_page, page->va_offset);
	list_move(&va_page->list, &epc->va_pages);

	return 0;
}

static inline bool sgx_virt_host_query(struct sgx_virt_epc *epc,
				       unsigned long hva, bool host_tracked)
{
	struct sgx_virt_epc_page *page;
	struct vm_area_struct *vma;
	unsigned long index;
	bool ret = false;

	down_read(&epc->mm->mmap_sem);
	down_write(&epc->lock);

	if (epc->dead)
		goto out_unlock;

	vma = find_vma_intersection(epc->mm, hva, hva + 1);
	if (!vma || vma->vm_private_data != epc)
		goto out_unlock;

	index = sgx_virt_epc_calc_index(vma, hva);
	page = radix_tree_lookup(&epc->page_tree, index);
	if (page) {
		if (host_tracked) {
			ret = page->host_tracked;
			page->host_tracked = false;
		} else {
			ret = page->host_locked;
			page->host_locked = false;
		}
	}

out_unlock:
	up_write(&epc->lock);
	up_read(&epc->mm->mmap_sem);
	return ret;
}

bool sgx_virt_host_tracked(void *epc, unsigned long hva)
{
	return sgx_virt_host_query(epc, hva, true);
}
EXPORT_SYMBOL_GPL(sgx_virt_host_tracked);

bool sgx_virt_host_locked(void *epc, unsigned long hva)
{
	return sgx_virt_host_query(epc, hva, false);
}
EXPORT_SYMBOL_GPL(sgx_virt_host_locked);
