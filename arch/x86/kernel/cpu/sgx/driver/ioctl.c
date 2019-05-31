// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-19 Intel Corporation.

#include <asm/mman.h>
#include <linux/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/security.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/suspend.h>
#include "driver.h"

struct sgx_add_page_req {
	struct sgx_encl *encl;
	struct sgx_encl_page *encl_page;
	struct sgx_secinfo secinfo;
	unsigned long mrmask;
	struct list_head list;
};

static int sgx_encl_grow(struct sgx_encl *encl)
{
	struct sgx_va_page *va_page;
	int ret;

	BUILD_BUG_ON(SGX_VA_SLOT_COUNT !=
		(SGX_ENCL_PAGE_VA_OFFSET_MASK >> 3) + 1);

	mutex_lock(&encl->lock);
	if (encl->flags & SGX_ENCL_DEAD) {
		mutex_unlock(&encl->lock);
		return -EFAULT;
	}

	if (!(encl->page_cnt % SGX_VA_SLOT_COUNT)) {
		mutex_unlock(&encl->lock);

		va_page = kzalloc(sizeof(*va_page), GFP_KERNEL);
		if (!va_page)
			return -ENOMEM;
		va_page->epc_page = sgx_alloc_va_page();
		if (IS_ERR(va_page->epc_page)) {
			ret = PTR_ERR(va_page->epc_page);
			kfree(va_page);
			return ret;
		}

		mutex_lock(&encl->lock);
		if (encl->flags & SGX_ENCL_DEAD) {
			sgx_free_page(va_page->epc_page);
			kfree(va_page);
			mutex_unlock(&encl->lock);
			return -EFAULT;
		} else if (encl->page_cnt % SGX_VA_SLOT_COUNT) {
			sgx_free_page(va_page->epc_page);
			kfree(va_page);
		} else {
			list_add(&va_page->list, &encl->va_pages);
		}
	}
	encl->page_cnt++;
	mutex_unlock(&encl->lock);
	return 0;
}

static bool sgx_process_add_page_req(struct sgx_add_page_req *req,
				     struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *encl_page = req->encl_page;
	struct sgx_encl *encl = req->encl;
	unsigned long page_index = sgx_encl_get_index(encl, encl_page);
	struct sgx_secinfo secinfo;
	struct sgx_pageinfo pginfo;
	struct page *backing;
	unsigned long addr;
	int ret;
	int i;

	if (encl->flags & (SGX_ENCL_SUSPEND | SGX_ENCL_DEAD))
		return false;

	addr = SGX_ENCL_PAGE_ADDR(encl_page);

	backing = sgx_encl_get_backing_page(encl, page_index);
	if (IS_ERR(backing))
		return false;

	/*
	 * The SECINFO field must be 64-byte aligned, copy it to a local
	 * variable that is guaranteed to be aligned as req->secinfo may
	 * or may not be 64-byte aligned, e.g. req may have been allocated
	 * via kzalloc which is not aware of __aligned attributes.
	 */
	memcpy(&secinfo, &req->secinfo, sizeof(secinfo));

	pginfo.secs = (unsigned long)sgx_epc_addr(encl->secs.epc_page);
	pginfo.addr = addr;
	pginfo.metadata = (unsigned long)&secinfo;
	pginfo.contents = (unsigned long)kmap_atomic(backing);
	ret = __eadd(&pginfo, sgx_epc_addr(epc_page));
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	put_page(backing);

	if (ret) {
		if (encls_failed(ret))
			ENCLS_WARN(ret, "EADD");
		return false;
	}

	for_each_set_bit(i, &req->mrmask, 16) {
		ret = __eextend(sgx_epc_addr(encl->secs.epc_page),
				sgx_epc_addr(epc_page) + (i * 0x100));
		if (ret) {
			if (encls_failed(ret))
				ENCLS_WARN(ret, "EEXTEND");
			return false;
		}
	}

	encl_page->encl = encl;
	encl_page->epc_page = epc_page;
	encl->secs_child_cnt++;
	sgx_mark_page_reclaimable(encl_page->epc_page);

	return true;
}

static void sgx_add_page_worker(struct work_struct *work)
{
	struct sgx_add_page_req *req;
	bool skip_rest = false;
	bool is_empty = false;
	struct sgx_encl *encl;
	struct sgx_epc_page *epc_page;

	encl = container_of(work, struct sgx_encl, work);

	do {
		schedule();

		mutex_lock(&encl->lock);
		if (encl->flags & SGX_ENCL_DEAD)
			skip_rest = true;

		req = list_first_entry(&encl->add_page_reqs,
				       struct sgx_add_page_req, list);
		list_del(&req->list);
		is_empty = list_empty(&encl->add_page_reqs);
		mutex_unlock(&encl->lock);

		if (skip_rest)
			goto next;

		epc_page = sgx_alloc_page(req->encl_page, true);

		mutex_lock(&encl->lock);

		if (IS_ERR(epc_page)) {
			sgx_encl_destroy(encl);
			skip_rest = true;
		} else if (!sgx_process_add_page_req(req, epc_page)) {
			sgx_free_page(epc_page);
			sgx_encl_destroy(encl);
			skip_rest = true;
		}

		mutex_unlock(&encl->lock);

next:
		kfree(req);
	} while (!kref_put(&encl->refcount, sgx_encl_release) && !is_empty);
}

static u32 sgx_calc_ssaframesize(u32 miscselect, u64 xfrm)
{
	u32 size_max = PAGE_SIZE;
	u32 size;
	int i;

	for (i = 2; i < 64; i++) {
		if (!((1 << i) & xfrm))
			continue;

		size = SGX_SSA_GPRS_SIZE + sgx_xsave_size_tbl[i];
		if (miscselect & SGX_MISC_EXINFO)
			size += SGX_SSA_MISC_EXINFO_SIZE;

		if (size > size_max)
			size_max = size;
	}

	return PFN_UP(size_max);
}

static int sgx_validate_secs(const struct sgx_secs *secs,
			     unsigned long ssaframesize)
{
	if (secs->size < (2 * PAGE_SIZE) || !is_power_of_2(secs->size))
		return -EINVAL;

	if (secs->base & (secs->size - 1))
		return -EINVAL;

	if (secs->miscselect & sgx_misc_reserved_mask ||
	    secs->attributes & sgx_attributes_reserved_mask ||
	    secs->xfrm & sgx_xfrm_reserved_mask)
		return -EINVAL;

	if (secs->attributes & SGX_ATTR_MODE64BIT) {
		if (secs->size > sgx_encl_size_max_64)
			return -EINVAL;
	} else if (secs->size > sgx_encl_size_max_32)
		return -EINVAL;

	if (!(secs->xfrm & XFEATURE_MASK_FP) ||
	    !(secs->xfrm & XFEATURE_MASK_SSE) ||
	    (((secs->xfrm >> XFEATURE_BNDREGS) & 1) !=
	     ((secs->xfrm >> XFEATURE_BNDCSR) & 1)))
		return -EINVAL;

	if (!secs->ssa_frame_size || ssaframesize > secs->ssa_frame_size)
		return -EINVAL;

	if (memchr_inv(secs->reserved1, 0, SGX_SECS_RESERVED1_SIZE) ||
	    memchr_inv(secs->reserved2, 0, SGX_SECS_RESERVED2_SIZE) ||
	    memchr_inv(secs->reserved3, 0, SGX_SECS_RESERVED3_SIZE) ||
	    memchr_inv(secs->reserved4, 0, SGX_SECS_RESERVED4_SIZE))
		return -EINVAL;

	return 0;
}

static struct sgx_encl_page *sgx_encl_page_alloc(struct sgx_encl *encl,
						 unsigned long addr,
						 unsigned long prot)
{
	struct sgx_encl_page *encl_page;
	int ret;

	if (radix_tree_lookup(&encl->page_tree, PFN_DOWN(addr)))
		return ERR_PTR(-EEXIST);
	encl_page = kzalloc(sizeof(*encl_page), GFP_KERNEL);
	if (!encl_page)
		return ERR_PTR(-ENOMEM);
	encl_page->desc = addr;
	encl_page->encl = encl;
	encl_page->vm_prot_bits = calc_vm_prot_bits(prot, 0);
	ret = radix_tree_insert(&encl->page_tree, PFN_DOWN(encl_page->desc),
				encl_page);
	if (ret) {
		kfree(encl_page);
		return ERR_PTR(ret);
	}
	return encl_page;
}

static int sgx_encl_pm_notifier(struct notifier_block *nb,
				unsigned long action, void *data)
{
	struct sgx_encl *encl = container_of(nb, struct sgx_encl, pm_notifier);

	if (action != PM_SUSPEND_PREPARE && action != PM_HIBERNATION_PREPARE)
		return NOTIFY_DONE;

	mutex_lock(&encl->lock);
	sgx_encl_destroy(encl);
	encl->flags |= SGX_ENCL_SUSPEND;
	mutex_unlock(&encl->lock);
	flush_work(&encl->work);
	return NOTIFY_DONE;
}

static int sgx_encl_create(struct sgx_encl *encl, struct sgx_secs *secs)
{
	unsigned long encl_size = secs->size + PAGE_SIZE;
	struct sgx_epc_page *secs_epc;
	unsigned long ssaframesize;
	struct sgx_pageinfo pginfo;
	struct sgx_secinfo secinfo;
	struct file *backing;
	long ret;

	ret = sgx_encl_grow(encl);
	if (ret)
		return ret;

	mutex_lock(&encl->lock);

	if (encl->flags & SGX_ENCL_CREATED) {
		ret = -EFAULT;
		goto err_out;
	}

	ssaframesize = sgx_calc_ssaframesize(secs->miscselect, secs->xfrm);
	if (sgx_validate_secs(secs, ssaframesize)) {
		ret = -EINVAL;
		goto err_out;
	}

	backing = shmem_file_setup("SGX backing", encl_size + (encl_size >> 5),
				   VM_NORESERVE);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		goto err_out;
	}

	encl->backing = backing;

	INIT_WORK(&encl->work, sgx_add_page_worker);

	secs_epc = sgx_alloc_page(&encl->secs, true);
	if (IS_ERR(secs_epc)) {
		ret = PTR_ERR(secs_epc);
		goto err_out;
	}

	encl->secs.epc_page = secs_epc;

	pginfo.addr = 0;
	pginfo.contents = (unsigned long)secs;
	pginfo.metadata = (unsigned long)&secinfo;
	pginfo.secs = 0;
	memset(&secinfo, 0, sizeof(secinfo));

	ret = __ecreate((void *)&pginfo, sgx_epc_addr(secs_epc));
	if (ret) {
		pr_debug("ECREATE returned %ld\n", ret);
		goto err_out;
	}

	if (secs->attributes & SGX_ATTR_DEBUG)
		encl->flags |= SGX_ENCL_DEBUG;

	encl->pm_notifier.notifier_call = &sgx_encl_pm_notifier;
	ret = register_pm_notifier(&encl->pm_notifier);
	if (ret) {
		encl->pm_notifier.notifier_call = NULL;
		goto err_out;
	}

	encl->secs.encl = encl;
	encl->secs_attributes = secs->attributes;
	encl->allowed_attributes = SGX_ATTR_ALLOWED_MASK;
	encl->base = secs->base;
	encl->size = secs->size;
	encl->ssaframesize = secs->ssa_frame_size;
	encl->flags |= SGX_ENCL_CREATED;

	mutex_unlock(&encl->lock);
	return 0;

err_out:
	if (encl->secs.epc_page) {
		sgx_free_page(encl->secs.epc_page);
		encl->secs.epc_page = NULL;
	}

	if (encl->backing) {
		fput(encl->backing);
		encl->backing = NULL;
	}

	mutex_unlock(&encl->lock);
	return ret;
}

/**
 * sgx_ioc_enclave_create - handler for %SGX_IOC_ENCLAVE_CREATE
 * @filep:	open file to /dev/sgx
 * @arg:	userspace pointer to a struct sgx_enclave_create instance
 *
 * Allocate kernel data structures for a new enclave and execute ECREATE after
 * verifying the correctness of the provided SECS.
 *
 * Note, enforcement of restricted and disallowed attributes is deferred until
 * sgx_ioc_enclave_init(), only the architectural correctness of the SECS is
 * checked by sgx_ioc_enclave_create().
 *
 * Return:
 *   0 on success,
 *   -errno otherwise
 */
static long sgx_ioc_enclave_create(struct file *filep, void __user *arg)
{
	struct sgx_encl *encl = filep->private_data;
	struct sgx_enclave_create ecreate;
	struct page *secs_page;
	struct sgx_secs *secs;
	int ret;

	if (copy_from_user(&ecreate, arg, sizeof(ecreate)))
		return -EFAULT;

	secs_page = alloc_page(GFP_HIGHUSER);
	if (!secs_page)
		return -ENOMEM;

	secs = kmap(secs_page);
	if (copy_from_user(secs, (void __user *)ecreate.src, sizeof(*secs))) {
		ret = -EFAULT;
		goto out;
	}

	ret = sgx_encl_create(encl, secs);

out:
	kunmap(secs_page);
	__free_page(secs_page);
	return ret;
}

static int sgx_validate_secinfo(struct sgx_secinfo *secinfo)
{
	u64 page_type = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;
	u64 perm = secinfo->flags & SGX_SECINFO_PERMISSION_MASK;
	int i;

	if ((secinfo->flags & SGX_SECINFO_RESERVED_MASK) ||
	    ((perm & SGX_SECINFO_W) && !(perm & SGX_SECINFO_R)) ||
	    (page_type != SGX_SECINFO_TCS && page_type != SGX_SECINFO_TRIM &&
	     page_type != SGX_SECINFO_REG))
		return -EINVAL;

	for (i = 0; i < SGX_SECINFO_RESERVED_SIZE; i++)
		if (secinfo->reserved[i])
			return -EINVAL;

	return 0;
}

static bool sgx_validate_offset(struct sgx_encl *encl, unsigned long offset)
{
	if (offset & (PAGE_SIZE - 1))
		return false;

	if (offset >= encl->size)
		return false;

	return true;
}

static int sgx_validate_tcs(struct sgx_encl *encl, struct sgx_tcs *tcs)
{
	int i;

	if (tcs->flags & SGX_TCS_RESERVED_MASK)
		return -EINVAL;

	if (tcs->flags & SGX_TCS_DBGOPTIN)
		return -EINVAL;

	if (!sgx_validate_offset(encl, tcs->ssa_offset))
		return -EINVAL;

	if (!sgx_validate_offset(encl, tcs->fs_offset))
		return -EINVAL;

	if (!sgx_validate_offset(encl, tcs->gs_offset))
		return -EINVAL;

	if ((tcs->fs_limit & 0xFFF) != 0xFFF)
		return -EINVAL;

	if ((tcs->gs_limit & 0xFFF) != 0xFFF)
		return -EINVAL;

	for (i = 0; i < SGX_TCS_RESERVED_SIZE; i++)
		if (tcs->reserved[i])
			return -EINVAL;

	return 0;
}

static int __sgx_encl_add_page(struct sgx_encl *encl,
			       struct sgx_encl_page *encl_page,
			       void *data,
			       struct sgx_secinfo *secinfo,
			       unsigned int mrmask)
{
	unsigned long page_index = sgx_encl_get_index(encl, encl_page);
	u64 page_type = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;
	struct sgx_add_page_req *req = NULL;
	struct page *backing;
	void *backing_ptr;
	int empty;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	backing = sgx_encl_get_backing_page(encl, page_index);
	if (IS_ERR(backing)) {
		kfree(req);
		return PTR_ERR(backing);
	}

	backing_ptr = kmap(backing);
	memcpy(backing_ptr, data, PAGE_SIZE);
	kunmap(backing);
	if (page_type == SGX_SECINFO_TCS)
		encl_page->desc |= SGX_ENCL_PAGE_TCS;
	memcpy(&req->secinfo, secinfo, sizeof(*secinfo));
	req->encl = encl;
	req->encl_page = encl_page;
	req->mrmask = mrmask;
	empty = list_empty(&encl->add_page_reqs);
	kref_get(&encl->refcount);
	list_add_tail(&req->list, &encl->add_page_reqs);
	if (empty)
		queue_work(sgx_encl_wq, &encl->work);
	set_page_dirty(backing);
	put_page(backing);
	return 0;
}

static int sgx_encl_add_page(struct sgx_encl *encl, unsigned long addr,
			     void *data, struct sgx_secinfo *secinfo,
			     unsigned int mrmask, unsigned long prot)
{
	u64 page_type = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;
	struct sgx_encl_page *encl_page;
	int ret;

	if (sgx_validate_secinfo(secinfo))
		return -EINVAL;
	if (page_type == SGX_SECINFO_TCS) {
		ret = sgx_validate_tcs(encl, data);
		if (ret)
			return ret;
	}

	ret = sgx_encl_grow(encl);
	if (ret)
		return ret;

	mutex_lock(&encl->lock);

	if (!(encl->flags & SGX_ENCL_CREATED) ||
	    (encl->flags & (SGX_ENCL_INITIALIZED | SGX_ENCL_DEAD))) {
		ret = -EFAULT;
		goto out;
	}

	encl_page = sgx_encl_page_alloc(encl, addr, prot);
	if (IS_ERR(encl_page)) {
		ret = PTR_ERR(encl_page);
		goto out;
	}

	ret = __sgx_encl_add_page(encl, encl_page, data, secinfo, mrmask);
	if (ret) {
		radix_tree_delete(&encl_page->encl->page_tree,
				  PFN_DOWN(encl_page->desc));
		kfree(encl_page);
	}

out:
	mutex_unlock(&encl->lock);
	return ret;
}

static int sgx_encl_page_copy(void *dst, unsigned long src, unsigned long prot,
			      u16 mrmask)
{
	struct vm_area_struct *vma;
	int ret;

	/* Hold mmap_sem across copy_from_user() to avoid a TOCTOU race. */
	down_read(&current->mm->mmap_sem);

	vma = find_vma(current->mm, src);
	if (!vma) {
		ret = -EFAULT;
		goto out;
	}

	/* Query vma's VM_MAYEXEC as an indirect path_noexec() check. */
	if ((prot & PROT_EXEC) && !(vma->vm_flags & VM_MAYEXEC)) {
		ret = -EACCES;
		goto out;
	}

	ret = security_enclave_load(vma, prot, mrmask == 0xffff);
	if (ret)
		goto out;

	if (copy_from_user(dst, (void __user *)src, PAGE_SIZE))
		ret = -EFAULT;

out:
	up_read(&current->mm->mmap_sem);

	return ret;
}

/**
 * sgx_ioc_enclave_add_page - handler for %SGX_IOC_ENCLAVE_ADD_PAGE
 *
 * @filep:	open file to /dev/sgx
 * @arg:	userspace pointer to a struct sgx_enclave_add_page instance
 *
 * Add a page to an uninitialized enclave (EADD), and optionally extend the
 * enclave's measurement with the contents of the page (EEXTEND).  EADD and
 * EEXTEND are done asynchronously via worker threads.  A successful
 * sgx_ioc_enclave_add_page() only indicates the page has been added to the
 * work queue, it does not guarantee adding the page to the enclave will
 * succeed.
 *
 * Return:
 *   0 on success,
 *   -errno otherwise
 */
static long sgx_ioc_enclave_add_page(struct file *filep, void __user *arg)
{
	struct sgx_encl *encl = filep->private_data;
	struct sgx_enclave_add_page addp;
	struct sgx_secinfo secinfo;
	struct page *data_page;
	unsigned long prot;
	void *data;
	int ret;

	if (copy_from_user(&addp, arg, sizeof(addp)))
		return -EFAULT;

	if (copy_from_user(&secinfo, (void __user *)addp.secinfo,
			   sizeof(secinfo)))
		return -EFAULT;

	data_page = alloc_page(GFP_HIGHUSER);
	if (!data_page)
		return -ENOMEM;

	data = kmap(data_page);

	prot = addp.flags & (PROT_READ | PROT_WRITE | PROT_EXEC);

	ret = sgx_encl_page_copy(data, addp.src, prot, addp.mrmask);
	if (ret)
		goto out;

	ret = sgx_encl_add_page(encl, addp.addr, data, &secinfo, addp.mrmask,
				prot);
	if (ret)
		goto out;

out:
	kunmap(data_page);
	__free_page(data_page);
	return ret;
}

static int __sgx_get_key_hash(struct crypto_shash *tfm, const void *modulus,
			      void *hash)
{
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tfm;

	return crypto_shash_digest(shash, modulus, SGX_MODULUS_SIZE, hash);
}

static int sgx_get_key_hash(const void *modulus, void *hash)
{
	struct crypto_shash *tfm;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = __sgx_get_key_hash(tfm, modulus, hash);

	crypto_free_shash(tfm);
	return ret;
}

static int sgx_encl_init(struct sgx_encl *encl, struct sgx_sigstruct *sigstruct,
			 struct sgx_einittoken *token)
{
	u64 mrsigner[4];
	int ret;
	int i;
	int j;

	/* Check that the required attributes have been authorized. */
	if (encl->secs_attributes & ~encl->allowed_attributes)
		return -EINVAL;

	ret = sgx_get_key_hash(sigstruct->modulus, mrsigner);
	if (ret)
		return ret;

	flush_work(&encl->work);

	mutex_lock(&encl->lock);

	if (!(encl->flags & SGX_ENCL_CREATED) ||
	    (encl->flags & (SGX_ENCL_INITIALIZED | SGX_ENCL_DEAD))) {
		ret = -EFAULT;
		goto err_out;
	}

	for (i = 0; i < SGX_EINIT_SLEEP_COUNT; i++) {
		for (j = 0; j < SGX_EINIT_SPIN_COUNT; j++) {
			ret = sgx_einit(sigstruct, token, encl->secs.epc_page,
					mrsigner);
			if (ret == SGX_UNMASKED_EVENT)
				continue;
			else
				break;
		}

		if (ret != SGX_UNMASKED_EVENT)
			break;

		msleep_interruptible(SGX_EINIT_SLEEP_TIME);

		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			goto err_out;
		}
	}

	if (encls_faulted(ret)) {
		if (encls_failed(ret))
			ENCLS_WARN(ret, "EINIT");

		sgx_encl_destroy(encl);
		ret = -EFAULT;
	} else if (encls_returned_code(ret)) {
		pr_debug("EINIT returned %d\n", ret);
	} else {
		encl->flags |= SGX_ENCL_INITIALIZED;
	}

err_out:
	mutex_unlock(&encl->lock);
	return ret;
}

/**
 * sgx_ioc_enclave_init - handler for %SGX_IOC_ENCLAVE_INIT
 *
 * @filep:	open file to /dev/sgx
 * @arg:	userspace pointer to a struct sgx_enclave_init instance
 *
 * Flush any outstanding enqueued EADD operations and perform EINIT.  The
 * Launch Enclave Public Key Hash MSRs are rewritten as necessary to match
 * the enclave's MRSIGNER, which is caculated from the provided sigstruct.
 *
 * Return:
 *   0 on success,
 *   SGX error code on EINIT failure,
 *   -errno otherwise
 */
static long sgx_ioc_enclave_init(struct file *filep, void __user *arg)
{
	struct sgx_encl *encl = filep->private_data;
	struct sgx_einittoken *einittoken;
	struct sgx_sigstruct *sigstruct;
	struct sgx_enclave_init einit;
	struct page *initp_page;
	int ret;

	if (copy_from_user(&einit, arg, sizeof(einit)))
		return -EFAULT;

	initp_page = alloc_page(GFP_HIGHUSER);
	if (!initp_page)
		return -ENOMEM;

	sigstruct = kmap(initp_page);
	einittoken = (struct sgx_einittoken *)
		((unsigned long)sigstruct + PAGE_SIZE / 2);
	memset(einittoken, 0, sizeof(*einittoken));

	if (copy_from_user(sigstruct, (void __user *)einit.sigstruct,
			   sizeof(*sigstruct))) {
		ret = -EFAULT;
		goto out;
	}

	ret = sgx_encl_init(encl, sigstruct, einittoken);

out:
	kunmap(initp_page);
	__free_page(initp_page);
	return ret;
}

/**
 * sgx_ioc_enclave_set_attribute - handler for %SGX_IOC_ENCLAVE_SET_ATTRIBUTE
 * @filep:	open file to /dev/sgx
 * @arg:	userspace pointer to a struct sgx_enclave_set_attribute instance
 *
 * Mark the enclave as being allowed to access a restricted attribute bit.
 * The requested attribute is specified via the attribute_fd field in the
 * provided struct sgx_enclave_set_attribute.  The attribute_fd must be a
 * handle to an SGX attribute file, e.g. “/dev/sgx/provision".
 *
 * Failure to explicitly request access to a restricted attribute will cause
 * sgx_ioc_enclave_init() to fail.  Currently, the only restricted attribute
 * is access to the PROVISION_KEY.
 *
 * Note, access to the EINITTOKEN_KEY is disallowed entirely.
 *
 * Return: 0 on success, -errno otherwise
 */
static long sgx_ioc_enclave_set_attribute(struct file *filep, void __user *arg)
{
	struct sgx_encl *encl = filep->private_data;
	struct sgx_enclave_set_attribute params;
	struct file *attribute_file;
	int ret;

	if (copy_from_user(&params, arg, sizeof(params)))
		return -EFAULT;

	attribute_file = fget(params.attribute_fd);
	if (!attribute_file->f_op)
		return -EINVAL;

	if (attribute_file->f_op != &sgx_provision_fops) {
		ret = -EINVAL;
		goto out;
	}

	encl->allowed_attributes |= SGX_ATTR_PROVISIONKEY;

out:
	fput(attribute_file);
	return ret;
}

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		return sgx_ioc_enclave_create(filep, (void __user *)arg);
	case SGX_IOC_ENCLAVE_ADD_PAGE:
		return sgx_ioc_enclave_add_page(filep, (void __user *)arg);
	case SGX_IOC_ENCLAVE_INIT:
		return sgx_ioc_enclave_init(filep, (void __user *)arg);
	case SGX_IOC_ENCLAVE_SET_ATTRIBUTE:
		return sgx_ioc_enclave_set_attribute(filep, (void __user *)arg);
	default:
		return -ENOIOCTLCMD;
	}
}
