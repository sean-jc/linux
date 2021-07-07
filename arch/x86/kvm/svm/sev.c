// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * AMD SVM-SEV support
 *
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 */

#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/psp-sev.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/misc_cgroup.h>
#include <linux/processor.h>
#include <linux/trace_events.h>
#include <linux/sev.h>
#include <linux/kvm_host.h>
#include <linux/sev-guest.h>
#include <asm/fpu/internal.h>

#include <asm/pkru.h>
#include <asm/trapnr.h>
#include <asm/sev.h>

#include "x86.h"
#include "svm.h"
#include "svm_ops.h"
#include "cpuid.h"
#include "trace.h"
#include "mmu.h"

#define __ex(x) __kvm_handle_fault_on_reboot(x)

#ifndef CONFIG_KVM_AMD_SEV
/*
 * When this config is not defined, SEV feature is not supported and APIs in
 * this file are not used but this file still gets compiled into the KVM AMD
 * module.
 *
 * We will not have MISC_CG_RES_SEV and MISC_CG_RES_SEV_ES entries in the enum
 * misc_res_type {} defined in linux/misc_cgroup.h.
 *
 * Below macros allow compilation to succeed.
 */
#define MISC_CG_RES_SEV MISC_CG_RES_TYPES
#define MISC_CG_RES_SEV_ES MISC_CG_RES_TYPES
#endif

#ifdef CONFIG_KVM_AMD_SEV
/* enable/disable SEV support */
static bool sev_enabled = true;
module_param_named(sev, sev_enabled, bool, 0444);

/* enable/disable SEV-ES support */
static bool sev_es_enabled = true;
module_param_named(sev_es, sev_es_enabled, bool, 0444);

/* enable/disable SEV-SNP support */
static bool sev_snp_enabled = true;
module_param_named(sev_snp, sev_snp_enabled, bool, 0444);
#else
#define sev_enabled false
#define sev_es_enabled false
#define sev_snp_enabled  false
#endif /* CONFIG_KVM_AMD_SEV */

#define AP_RESET_HOLD_NONE		0
#define AP_RESET_HOLD_NAE_EVENT		1
#define AP_RESET_HOLD_MSR_PROTO		2

static u8 sev_enc_bit;
static DECLARE_RWSEM(sev_deactivate_lock);
static DEFINE_MUTEX(sev_bitmap_lock);
unsigned int max_sev_asid;
static unsigned int min_sev_asid;
static unsigned long sev_me_mask;
static unsigned long *sev_asid_bitmap;
static unsigned long *sev_reclaim_asid_bitmap;

static int snp_decommission_context(struct kvm *kvm);

struct enc_region {
	struct list_head list;
	unsigned long npages;
	struct page **pages;
	unsigned long uaddr;
	unsigned long size;
};

/* Called with the sev_bitmap_lock held, or on shutdown  */
static int sev_flush_asids(int min_asid, int max_asid)
{
	int ret, pos, error = 0;

	/* Check if there are any ASIDs to reclaim before performing a flush */
	pos = find_next_bit(sev_reclaim_asid_bitmap, max_asid, min_asid);
	if (pos >= max_asid)
		return -EBUSY;

	/*
	 * DEACTIVATE will clear the WBINVD indicator causing DF_FLUSH to fail,
	 * so it must be guarded.
	 */
	down_write(&sev_deactivate_lock);

	wbinvd_on_all_cpus();
	ret = sev_guest_df_flush(&error);

	up_write(&sev_deactivate_lock);

	if (ret)
		pr_err("SEV: DF_FLUSH failed, ret=%d, error=%#x\n", ret, error);

	return ret;
}

static inline bool is_mirroring_enc_context(struct kvm *kvm)
{
	return !!to_kvm_svm(kvm)->sev_info.enc_context_owner;
}

/* Must be called with the sev_bitmap_lock held */
static bool __sev_recycle_asids(int min_asid, int max_asid)
{
	if (sev_flush_asids(min_asid, max_asid))
		return false;

	/* The flush process will flush all reclaimable SEV and SEV-ES ASIDs */
	bitmap_xor(sev_asid_bitmap, sev_asid_bitmap, sev_reclaim_asid_bitmap,
		   max_sev_asid);
	bitmap_zero(sev_reclaim_asid_bitmap, max_sev_asid);

	return true;
}

static int sev_asid_new(struct kvm_sev_info *sev)
{
	int pos, min_asid, max_asid, ret;
	bool retry = true;
	enum misc_res_type type;

	type = sev->es_active ? MISC_CG_RES_SEV_ES : MISC_CG_RES_SEV;
	WARN_ON(sev->misc_cg);
	sev->misc_cg = get_current_misc_cg();
	ret = misc_cg_try_charge(type, sev->misc_cg, 1);
	if (ret) {
		put_misc_cg(sev->misc_cg);
		sev->misc_cg = NULL;
		return ret;
	}

	mutex_lock(&sev_bitmap_lock);

	/*
	 * SEV-enabled guests must use asid from min_sev_asid to max_sev_asid.
	 * SEV-ES-enabled guest can use from 1 to min_sev_asid - 1.
	 */
	min_asid = sev->es_active ? 0 : min_sev_asid - 1;
	max_asid = sev->es_active ? min_sev_asid - 1 : max_sev_asid;
again:
	pos = find_next_zero_bit(sev_asid_bitmap, max_sev_asid, min_asid);
	if (pos >= max_asid) {
		if (retry && __sev_recycle_asids(min_asid, max_asid)) {
			retry = false;
			goto again;
		}
		mutex_unlock(&sev_bitmap_lock);
		ret = -EBUSY;
		goto e_uncharge;
	}

	__set_bit(pos, sev_asid_bitmap);

	mutex_unlock(&sev_bitmap_lock);

	return pos + 1;
e_uncharge:
	misc_cg_uncharge(type, sev->misc_cg, 1);
	put_misc_cg(sev->misc_cg);
	sev->misc_cg = NULL;
	return ret;
}

static int sev_get_asid(struct kvm *kvm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return sev->asid;
}

static void sev_asid_free(struct kvm_sev_info *sev)
{
	struct svm_cpu_data *sd;
	int cpu, pos;
	enum misc_res_type type;

	mutex_lock(&sev_bitmap_lock);

	pos = sev->asid - 1;
	__set_bit(pos, sev_reclaim_asid_bitmap);

	for_each_possible_cpu(cpu) {
		sd = per_cpu(svm_data, cpu);
		sd->sev_vmcbs[pos] = NULL;
	}

	mutex_unlock(&sev_bitmap_lock);

	type = sev->es_active ? MISC_CG_RES_SEV_ES : MISC_CG_RES_SEV;
	misc_cg_uncharge(type, sev->misc_cg, 1);
	put_misc_cg(sev->misc_cg);
	sev->misc_cg = NULL;
}

static void sev_decommission(unsigned int handle)
{
	struct sev_data_decommission decommission;

	if (!handle)
		return;

	decommission.handle = handle;
	sev_guest_decommission(&decommission, NULL);
}

static void sev_unbind_asid(struct kvm *kvm, unsigned int handle)
{
	struct sev_data_deactivate deactivate;

	if (!handle)
		return;

	deactivate.handle = handle;

	/* Guard DEACTIVATE against WBINVD/DF_FLUSH used in ASID recycling */
	down_read(&sev_deactivate_lock);
	sev_guest_deactivate(&deactivate, NULL);
	up_read(&sev_deactivate_lock);

	sev_decommission(handle);
}

static int verify_snp_init_flags(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_snp_init params;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	if (params.flags)
		return -EINVAL;

	return 0;
}

static int sev_guest_init(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	bool es_active = (argp->id == KVM_SEV_ES_INIT || argp->id == KVM_SEV_SNP_INIT);
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	bool snp_active = argp->id == KVM_SEV_SNP_INIT;
	int asid, ret;

	if (kvm->created_vcpus)
		return -EINVAL;

	ret = -EBUSY;
	if (unlikely(sev->active))
		return ret;

	sev->es_active = es_active;
	sev->snp_active = snp_active;
	asid = sev_asid_new(sev);
	if (asid < 0)
		goto e_no_asid;
	sev->asid = asid;

	if (snp_active) {
		ret = verify_snp_init_flags(kvm, argp);
		if (ret)
			goto e_free;

		ret = sev_snp_init(&argp->error);
	} else {
		ret = sev_platform_init(&argp->error);
	}

	if (ret)
		goto e_free;

	sev->active = true;
	sev->asid = asid;
	INIT_LIST_HEAD(&sev->regions_list);

	return 0;

e_free:
	sev_asid_free(sev);
	sev->asid = 0;
e_no_asid:
	sev->es_active = false;
	return ret;
}

static int sev_bind_asid(struct kvm *kvm, unsigned int handle, int *error)
{
	struct sev_data_activate activate;
	int asid = sev_get_asid(kvm);
	int ret;

	/* activate ASID on the given handle */
	activate.handle = handle;
	activate.asid   = asid;
	ret = sev_guest_activate(&activate, error);

	return ret;
}

static int __sev_issue_cmd(int fd, int id, void *data, int *error)
{
	struct fd f;
	int ret;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = sev_issue_cmd_external_user(f.file, id, data, error);

	fdput(f);
	return ret;
}

static int sev_issue_cmd(struct kvm *kvm, int id, void *data, int *error)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return __sev_issue_cmd(sev->fd, id, data, error);
}

static int sev_launch_start(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_start start;
	struct kvm_sev_launch_start params;
	void *dh_blob, *session_blob;
	int *error = &argp->error;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	memset(&start, 0, sizeof(start));

	dh_blob = NULL;
	if (params.dh_uaddr) {
		dh_blob = psp_copy_user_blob(params.dh_uaddr, params.dh_len);
		if (IS_ERR(dh_blob))
			return PTR_ERR(dh_blob);

		start.dh_cert_address = __sme_set(__pa(dh_blob));
		start.dh_cert_len = params.dh_len;
	}

	session_blob = NULL;
	if (params.session_uaddr) {
		session_blob = psp_copy_user_blob(params.session_uaddr, params.session_len);
		if (IS_ERR(session_blob)) {
			ret = PTR_ERR(session_blob);
			goto e_free_dh;
		}

		start.session_address = __sme_set(__pa(session_blob));
		start.session_len = params.session_len;
	}

	start.handle = params.handle;
	start.policy = params.policy;

	/* create memory encryption context */
	ret = __sev_issue_cmd(argp->sev_fd, SEV_CMD_LAUNCH_START, &start, error);
	if (ret)
		goto e_free_session;

	/* Bind ASID to this guest */
	ret = sev_bind_asid(kvm, start.handle, error);
	if (ret) {
		sev_decommission(start.handle);
		goto e_free_session;
	}

	/* return handle to userspace */
	params.handle = start.handle;
	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params, sizeof(params))) {
		sev_unbind_asid(kvm, start.handle);
		ret = -EFAULT;
		goto e_free_session;
	}

	sev->handle = start.handle;
	sev->fd = argp->sev_fd;

e_free_session:
	kfree(session_blob);
e_free_dh:
	kfree(dh_blob);
	return ret;
}

static struct page **sev_pin_memory(struct kvm *kvm, unsigned long uaddr,
				    unsigned long ulen, unsigned long *n,
				    int write)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	unsigned long npages, size;
	int npinned;
	unsigned long locked, lock_limit;
	struct page **pages;
	unsigned long first, last;
	int ret;

	lockdep_assert_held(&kvm->lock);

	if (ulen == 0 || uaddr + ulen < uaddr)
		return ERR_PTR(-EINVAL);

	/* Calculate number of pages. */
	first = (uaddr & PAGE_MASK) >> PAGE_SHIFT;
	last = ((uaddr + ulen - 1) & PAGE_MASK) >> PAGE_SHIFT;
	npages = (last - first + 1);

	locked = sev->pages_locked + npages;
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	if (locked > lock_limit && !capable(CAP_IPC_LOCK)) {
		pr_err("SEV: %lu locked pages exceed the lock limit of %lu.\n", locked, lock_limit);
		return ERR_PTR(-ENOMEM);
	}

	if (WARN_ON_ONCE(npages > INT_MAX))
		return ERR_PTR(-EINVAL);

	/* Avoid using vmalloc for smaller buffers. */
	size = npages * sizeof(struct page *);
	if (size > PAGE_SIZE)
		pages = __vmalloc(size, GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	else
		pages = kmalloc(size, GFP_KERNEL_ACCOUNT);

	if (!pages)
		return ERR_PTR(-ENOMEM);

	/* Pin the user virtual address. */
	npinned = pin_user_pages_fast(uaddr, npages, write ? FOLL_WRITE : 0, pages);
	if (npinned != npages) {
		pr_err("SEV: Failure locking %lu pages.\n", npages);
		ret = -ENOMEM;
		goto err;
	}

	*n = npages;
	sev->pages_locked = locked;

	return pages;

err:
	if (npinned > 0)
		unpin_user_pages(pages, npinned);

	kvfree(pages);
	return ERR_PTR(ret);
}

static void sev_unpin_memory(struct kvm *kvm, struct page **pages,
			     unsigned long npages)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	unpin_user_pages(pages, npages);
	kvfree(pages);
	sev->pages_locked -= npages;
}

static void sev_clflush_pages(struct page *pages[], unsigned long npages)
{
	uint8_t *page_virtual;
	unsigned long i;

	if (this_cpu_has(X86_FEATURE_SME_COHERENT) || npages == 0 ||
	    pages == NULL)
		return;

	for (i = 0; i < npages; i++) {
		page_virtual = kmap_atomic(pages[i]);
		clflush_cache_range(page_virtual, PAGE_SIZE);
		kunmap_atomic(page_virtual);
	}
}

static unsigned long get_num_contig_pages(unsigned long idx,
				struct page **inpages, unsigned long npages)
{
	unsigned long paddr, next_paddr;
	unsigned long i = idx + 1, pages = 1;

	/* find the number of contiguous pages starting from idx */
	paddr = __sme_page_pa(inpages[idx]);
	while (i < npages) {
		next_paddr = __sme_page_pa(inpages[i++]);
		if ((paddr + PAGE_SIZE) == next_paddr) {
			pages++;
			paddr = next_paddr;
			continue;
		}
		break;
	}

	return pages;
}

static int sev_launch_update_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	unsigned long vaddr, vaddr_end, next_vaddr, npages, pages, size, i;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_launch_update_data params;
	struct sev_data_launch_update_data data;
	struct page **inpages;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	vaddr = params.uaddr;
	size = params.len;
	vaddr_end = vaddr + size;

	/* Lock the user memory. */
	inpages = sev_pin_memory(kvm, vaddr, size, &npages, 1);
	if (IS_ERR(inpages))
		return PTR_ERR(inpages);

	/*
	 * Flush (on non-coherent CPUs) before LAUNCH_UPDATE encrypts pages in
	 * place; the cache may contain the data that was written unencrypted.
	 */
	sev_clflush_pages(inpages, npages);

	data.reserved = 0;
	data.handle = sev->handle;

	for (i = 0; vaddr < vaddr_end; vaddr = next_vaddr, i += pages) {
		int offset, len;

		/*
		 * If the user buffer is not page-aligned, calculate the offset
		 * within the page.
		 */
		offset = vaddr & (PAGE_SIZE - 1);

		/* Calculate the number of pages that can be encrypted in one go. */
		pages = get_num_contig_pages(i, inpages, npages);

		len = min_t(size_t, ((pages * PAGE_SIZE) - offset), size);

		data.len = len;
		data.address = __sme_page_pa(inpages[i]) + offset;
		ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_UPDATE_DATA, &data, &argp->error);
		if (ret)
			goto e_unpin;

		size -= len;
		next_vaddr = vaddr + len;
	}

e_unpin:
	/* content of memory is updated, mark pages dirty */
	for (i = 0; i < npages; i++) {
		set_page_dirty_lock(inpages[i]);
		mark_page_accessed(inpages[i]);
	}
	/* unlock the user pages */
	sev_unpin_memory(kvm, inpages, npages);
	return ret;
}

static int sev_es_sync_vmsa(struct vcpu_svm *svm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(svm->vcpu.kvm)->sev_info;
	struct sev_es_save_area *save = svm->vmsa;

	/* Check some debug related fields before encrypting the VMSA */
	if (svm->vcpu.guest_debug || (svm->vmcb->save.dr7 & ~DR7_FIXED_1))
		return -EINVAL;

	/*
	 * SEV-ES will use a VMSA that is pointed to by the VMCB, not
	 * the traditional VMSA that is part of the VMCB. Copy the
	 * traditional VMSA as it has been built so far (in prep
	 * for LAUNCH_UPDATE_VMSA) to be the initial SEV-ES state.
	 */
	memcpy(save, &svm->vmcb->save, sizeof(svm->vmcb->save));

	/* Sync registgers */
	save->rax = svm->vcpu.arch.regs[VCPU_REGS_RAX];
	save->rbx = svm->vcpu.arch.regs[VCPU_REGS_RBX];
	save->rcx = svm->vcpu.arch.regs[VCPU_REGS_RCX];
	save->rdx = svm->vcpu.arch.regs[VCPU_REGS_RDX];
	save->rsp = svm->vcpu.arch.regs[VCPU_REGS_RSP];
	save->rbp = svm->vcpu.arch.regs[VCPU_REGS_RBP];
	save->rsi = svm->vcpu.arch.regs[VCPU_REGS_RSI];
	save->rdi = svm->vcpu.arch.regs[VCPU_REGS_RDI];
#ifdef CONFIG_X86_64
	save->r8  = svm->vcpu.arch.regs[VCPU_REGS_R8];
	save->r9  = svm->vcpu.arch.regs[VCPU_REGS_R9];
	save->r10 = svm->vcpu.arch.regs[VCPU_REGS_R10];
	save->r11 = svm->vcpu.arch.regs[VCPU_REGS_R11];
	save->r12 = svm->vcpu.arch.regs[VCPU_REGS_R12];
	save->r13 = svm->vcpu.arch.regs[VCPU_REGS_R13];
	save->r14 = svm->vcpu.arch.regs[VCPU_REGS_R14];
	save->r15 = svm->vcpu.arch.regs[VCPU_REGS_R15];
#endif
	save->rip = svm->vcpu.arch.regs[VCPU_REGS_RIP];

	/* Sync some non-GPR registers before encrypting */
	save->xcr0 = svm->vcpu.arch.xcr0;
	save->pkru = svm->vcpu.arch.pkru;
	save->xss  = svm->vcpu.arch.ia32_xss;

	if (sev_snp_guest(svm->vcpu.kvm))
		save->sev_features |= SVM_SEV_FEATURES_SNP_ACTIVE;

	/*
	 * Save the VMSA synced SEV features. For now, they are the same for
	 * all vCPUs, so just save each time.
	 */
	sev->sev_features = save->sev_features;

	return 0;
}

static int sev_launch_update_vmsa(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_update_vmsa vmsa;
	struct kvm_vcpu *vcpu;
	int i, ret;

	if (!sev_es_guest(kvm))
		return -ENOTTY;

	vmsa.reserved = 0;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct vcpu_svm *svm = to_svm(vcpu);

		/* Perform some pre-encryption checks against the VMSA */
		ret = sev_es_sync_vmsa(svm);
		if (ret)
			return ret;

		/*
		 * The LAUNCH_UPDATE_VMSA command will perform in-place
		 * encryption of the VMSA memory content (i.e it will write
		 * the same memory region with the guest's key), so invalidate
		 * it first.
		 */
		clflush_cache_range(svm->vmsa, PAGE_SIZE);

		vmsa.handle = sev->handle;
		vmsa.address = __sme_pa(svm->vmsa);
		vmsa.len = PAGE_SIZE;
		ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_UPDATE_VMSA, &vmsa,
				    &argp->error);
		if (ret)
			return ret;

		svm->vcpu.arch.guest_state_protected = true;
	}

	return 0;
}

static int sev_launch_measure(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	void __user *measure = (void __user *)(uintptr_t)argp->data;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_measure data;
	struct kvm_sev_launch_measure params;
	void __user *p = NULL;
	void *blob = NULL;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, measure, sizeof(params)))
		return -EFAULT;

	memset(&data, 0, sizeof(data));

	/* User wants to query the blob length */
	if (!params.len)
		goto cmd;

	p = (void __user *)(uintptr_t)params.uaddr;
	if (p) {
		if (params.len > SEV_FW_BLOB_MAX_SIZE)
			return -EINVAL;

		blob = kmalloc(params.len, GFP_KERNEL_ACCOUNT);
		if (!blob)
			return -ENOMEM;

		data.address = __psp_pa(blob);
		data.len = params.len;
	}

cmd:
	data.handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_MEASURE, &data, &argp->error);

	/*
	 * If we query the session length, FW responded with expected data.
	 */
	if (!params.len)
		goto done;

	if (ret)
		goto e_free_blob;

	if (blob) {
		if (copy_to_user(p, blob, params.len))
			ret = -EFAULT;
	}

done:
	params.len = data.len;
	if (copy_to_user(measure, &params, sizeof(params)))
		ret = -EFAULT;
e_free_blob:
	kfree(blob);
	return ret;
}

static int sev_launch_finish(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_finish data;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data.handle = sev->handle;
	return sev_issue_cmd(kvm, SEV_CMD_LAUNCH_FINISH, &data, &argp->error);
}

static int sev_guest_status(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_guest_status params;
	struct sev_data_guest_status data;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	memset(&data, 0, sizeof(data));

	data.handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_GUEST_STATUS, &data, &argp->error);
	if (ret)
		return ret;

	params.policy = data.policy;
	params.state = data.state;
	params.handle = data.handle;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params, sizeof(params)))
		ret = -EFAULT;

	return ret;
}

static int __sev_issue_dbg_cmd(struct kvm *kvm, unsigned long src,
			       unsigned long dst, int size,
			       int *error, bool enc)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_dbg data;

	data.reserved = 0;
	data.handle = sev->handle;
	data.dst_addr = dst;
	data.src_addr = src;
	data.len = size;

	return sev_issue_cmd(kvm,
			     enc ? SEV_CMD_DBG_ENCRYPT : SEV_CMD_DBG_DECRYPT,
			     &data, error);
}

static int __sev_dbg_decrypt(struct kvm *kvm, unsigned long src_paddr,
			     unsigned long dst_paddr, int sz, int *err)
{
	int offset;

	/*
	 * Its safe to read more than we are asked, caller should ensure that
	 * destination has enough space.
	 */
	offset = src_paddr & 15;
	src_paddr = round_down(src_paddr, 16);
	sz = round_up(sz + offset, 16);

	return __sev_issue_dbg_cmd(kvm, src_paddr, dst_paddr, sz, err, false);
}

static int __sev_dbg_decrypt_user(struct kvm *kvm, unsigned long paddr,
				  void __user *dst_uaddr,
				  unsigned long dst_paddr,
				  int size, int *err)
{
	struct page *tpage = NULL;
	int ret, offset;

	/* if inputs are not 16-byte then use intermediate buffer */
	if (!IS_ALIGNED(dst_paddr, 16) ||
	    !IS_ALIGNED(paddr,     16) ||
	    !IS_ALIGNED(size,      16)) {
		tpage = (void *)alloc_page(GFP_KERNEL);
		if (!tpage)
			return -ENOMEM;

		dst_paddr = __sme_page_pa(tpage);
	}

	ret = __sev_dbg_decrypt(kvm, paddr, dst_paddr, size, err);
	if (ret)
		goto e_free;

	if (tpage) {
		offset = paddr & 15;
		if (copy_to_user(dst_uaddr, page_address(tpage) + offset, size))
			ret = -EFAULT;
	}

e_free:
	if (tpage)
		__free_page(tpage);

	return ret;
}

static int __sev_dbg_encrypt_user(struct kvm *kvm, unsigned long paddr,
				  void __user *vaddr,
				  unsigned long dst_paddr,
				  void __user *dst_vaddr,
				  int size, int *error)
{
	struct page *src_tpage = NULL;
	struct page *dst_tpage = NULL;
	int ret, len = size;

	/* If source buffer is not aligned then use an intermediate buffer */
	if (!IS_ALIGNED((unsigned long)vaddr, 16)) {
		src_tpage = alloc_page(GFP_KERNEL);
		if (!src_tpage)
			return -ENOMEM;

		if (copy_from_user(page_address(src_tpage), vaddr, size)) {
			__free_page(src_tpage);
			return -EFAULT;
		}

		paddr = __sme_page_pa(src_tpage);
	}

	/*
	 *  If destination buffer or length is not aligned then do read-modify-write:
	 *   - decrypt destination in an intermediate buffer
	 *   - copy the source buffer in an intermediate buffer
	 *   - use the intermediate buffer as source buffer
	 */
	if (!IS_ALIGNED((unsigned long)dst_vaddr, 16) || !IS_ALIGNED(size, 16)) {
		int dst_offset;

		dst_tpage = alloc_page(GFP_KERNEL);
		if (!dst_tpage) {
			ret = -ENOMEM;
			goto e_free;
		}

		ret = __sev_dbg_decrypt(kvm, dst_paddr,
					__sme_page_pa(dst_tpage), size, error);
		if (ret)
			goto e_free;

		/*
		 *  If source is kernel buffer then use memcpy() otherwise
		 *  copy_from_user().
		 */
		dst_offset = dst_paddr & 15;

		if (src_tpage)
			memcpy(page_address(dst_tpage) + dst_offset,
			       page_address(src_tpage), size);
		else {
			if (copy_from_user(page_address(dst_tpage) + dst_offset,
					   vaddr, size)) {
				ret = -EFAULT;
				goto e_free;
			}
		}

		paddr = __sme_page_pa(dst_tpage);
		dst_paddr = round_down(dst_paddr, 16);
		len = round_up(size, 16);
	}

	ret = __sev_issue_dbg_cmd(kvm, paddr, dst_paddr, len, error, true);

e_free:
	if (src_tpage)
		__free_page(src_tpage);
	if (dst_tpage)
		__free_page(dst_tpage);
	return ret;
}

static int sev_dbg_crypt(struct kvm *kvm, struct kvm_sev_cmd *argp, bool dec)
{
	unsigned long vaddr, vaddr_end, next_vaddr;
	unsigned long dst_vaddr;
	struct page **src_p, **dst_p;
	struct kvm_sev_dbg debug;
	unsigned long n;
	unsigned int size;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&debug, (void __user *)(uintptr_t)argp->data, sizeof(debug)))
		return -EFAULT;

	if (!debug.len || debug.src_uaddr + debug.len < debug.src_uaddr)
		return -EINVAL;
	if (!debug.dst_uaddr)
		return -EINVAL;

	vaddr = debug.src_uaddr;
	size = debug.len;
	vaddr_end = vaddr + size;
	dst_vaddr = debug.dst_uaddr;

	for (; vaddr < vaddr_end; vaddr = next_vaddr) {
		int len, s_off, d_off;

		/* lock userspace source and destination page */
		src_p = sev_pin_memory(kvm, vaddr & PAGE_MASK, PAGE_SIZE, &n, 0);
		if (IS_ERR(src_p))
			return PTR_ERR(src_p);

		dst_p = sev_pin_memory(kvm, dst_vaddr & PAGE_MASK, PAGE_SIZE, &n, 1);
		if (IS_ERR(dst_p)) {
			sev_unpin_memory(kvm, src_p, n);
			return PTR_ERR(dst_p);
		}

		/*
		 * Flush (on non-coherent CPUs) before DBG_{DE,EN}CRYPT read or modify
		 * the pages; flush the destination too so that future accesses do not
		 * see stale data.
		 */
		sev_clflush_pages(src_p, 1);
		sev_clflush_pages(dst_p, 1);

		/*
		 * Since user buffer may not be page aligned, calculate the
		 * offset within the page.
		 */
		s_off = vaddr & ~PAGE_MASK;
		d_off = dst_vaddr & ~PAGE_MASK;
		len = min_t(size_t, (PAGE_SIZE - s_off), size);

		if (dec)
			ret = __sev_dbg_decrypt_user(kvm,
						     __sme_page_pa(src_p[0]) + s_off,
						     (void __user *)dst_vaddr,
						     __sme_page_pa(dst_p[0]) + d_off,
						     len, &argp->error);
		else
			ret = __sev_dbg_encrypt_user(kvm,
						     __sme_page_pa(src_p[0]) + s_off,
						     (void __user *)vaddr,
						     __sme_page_pa(dst_p[0]) + d_off,
						     (void __user *)dst_vaddr,
						     len, &argp->error);

		sev_unpin_memory(kvm, src_p, n);
		sev_unpin_memory(kvm, dst_p, n);

		if (ret)
			goto err;

		next_vaddr = vaddr + len;
		dst_vaddr = dst_vaddr + len;
		size -= len;
	}
err:
	return ret;
}

static int sev_launch_secret(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_secret data;
	struct kvm_sev_launch_secret params;
	struct page **pages;
	void *blob, *hdr;
	unsigned long n, i;
	int ret, offset;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	pages = sev_pin_memory(kvm, params.guest_uaddr, params.guest_len, &n, 1);
	if (IS_ERR(pages))
		return PTR_ERR(pages);

	/*
	 * Flush (on non-coherent CPUs) before LAUNCH_SECRET encrypts pages in
	 * place; the cache may contain the data that was written unencrypted.
	 */
	sev_clflush_pages(pages, n);

	/*
	 * The secret must be copied into contiguous memory region, lets verify
	 * that userspace memory pages are contiguous before we issue command.
	 */
	if (get_num_contig_pages(0, pages, n) != n) {
		ret = -EINVAL;
		goto e_unpin_memory;
	}

	memset(&data, 0, sizeof(data));

	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	data.guest_address = __sme_page_pa(pages[0]) + offset;
	data.guest_len = params.guest_len;

	blob = psp_copy_user_blob(params.trans_uaddr, params.trans_len);
	if (IS_ERR(blob)) {
		ret = PTR_ERR(blob);
		goto e_unpin_memory;
	}

	data.trans_address = __psp_pa(blob);
	data.trans_len = params.trans_len;

	hdr = psp_copy_user_blob(params.hdr_uaddr, params.hdr_len);
	if (IS_ERR(hdr)) {
		ret = PTR_ERR(hdr);
		goto e_free_blob;
	}
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;

	data.handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_UPDATE_SECRET, &data, &argp->error);

	kfree(hdr);

e_free_blob:
	kfree(blob);
e_unpin_memory:
	/* content of memory is updated, mark pages dirty */
	for (i = 0; i < n; i++) {
		set_page_dirty_lock(pages[i]);
		mark_page_accessed(pages[i]);
	}
	sev_unpin_memory(kvm, pages, n);
	return ret;
}

static int sev_get_attestation_report(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	void __user *report = (void __user *)(uintptr_t)argp->data;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_attestation_report data;
	struct kvm_sev_attestation_report params;
	void __user *p;
	void *blob = NULL;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	memset(&data, 0, sizeof(data));

	/* User wants to query the blob length */
	if (!params.len)
		goto cmd;

	p = (void __user *)(uintptr_t)params.uaddr;
	if (p) {
		if (params.len > SEV_FW_BLOB_MAX_SIZE)
			return -EINVAL;

		blob = kmalloc(params.len, GFP_KERNEL_ACCOUNT);
		if (!blob)
			return -ENOMEM;

		data.address = __psp_pa(blob);
		data.len = params.len;
		memcpy(data.mnonce, params.mnonce, sizeof(params.mnonce));
	}
cmd:
	data.handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_ATTESTATION_REPORT, &data, &argp->error);
	/*
	 * If we query the session length, FW responded with expected data.
	 */
	if (!params.len)
		goto done;

	if (ret)
		goto e_free_blob;

	if (blob) {
		if (copy_to_user(p, blob, params.len))
			ret = -EFAULT;
	}

done:
	params.len = data.len;
	if (copy_to_user(report, &params, sizeof(params)))
		ret = -EFAULT;
e_free_blob:
	kfree(blob);
	return ret;
}

/* Userspace wants to query session length. */
static int
__sev_send_start_query_session_length(struct kvm *kvm, struct kvm_sev_cmd *argp,
				      struct kvm_sev_send_start *params)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_start data;
	int ret;

	memset(&data, 0, sizeof(data));
	data.handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_START, &data, &argp->error);

	params->session_len = data.session_len;
	if (copy_to_user((void __user *)(uintptr_t)argp->data, params,
				sizeof(struct kvm_sev_send_start)))
		ret = -EFAULT;

	return ret;
}

static int sev_send_start(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_start data;
	struct kvm_sev_send_start params;
	void *amd_certs, *session_data;
	void *pdh_cert, *plat_certs;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
				sizeof(struct kvm_sev_send_start)))
		return -EFAULT;

	/* if session_len is zero, userspace wants to query the session length */
	if (!params.session_len)
		return __sev_send_start_query_session_length(kvm, argp,
				&params);

	/* some sanity checks */
	if (!params.pdh_cert_uaddr || !params.pdh_cert_len ||
	    !params.session_uaddr || params.session_len > SEV_FW_BLOB_MAX_SIZE)
		return -EINVAL;

	/* allocate the memory to hold the session data blob */
	session_data = kmalloc(params.session_len, GFP_KERNEL_ACCOUNT);
	if (!session_data)
		return -ENOMEM;

	/* copy the certificate blobs from userspace */
	pdh_cert = psp_copy_user_blob(params.pdh_cert_uaddr,
				params.pdh_cert_len);
	if (IS_ERR(pdh_cert)) {
		ret = PTR_ERR(pdh_cert);
		goto e_free_session;
	}

	plat_certs = psp_copy_user_blob(params.plat_certs_uaddr,
				params.plat_certs_len);
	if (IS_ERR(plat_certs)) {
		ret = PTR_ERR(plat_certs);
		goto e_free_pdh;
	}

	amd_certs = psp_copy_user_blob(params.amd_certs_uaddr,
				params.amd_certs_len);
	if (IS_ERR(amd_certs)) {
		ret = PTR_ERR(amd_certs);
		goto e_free_plat_cert;
	}

	/* populate the FW SEND_START field with system physical address */
	memset(&data, 0, sizeof(data));
	data.pdh_cert_address = __psp_pa(pdh_cert);
	data.pdh_cert_len = params.pdh_cert_len;
	data.plat_certs_address = __psp_pa(plat_certs);
	data.plat_certs_len = params.plat_certs_len;
	data.amd_certs_address = __psp_pa(amd_certs);
	data.amd_certs_len = params.amd_certs_len;
	data.session_address = __psp_pa(session_data);
	data.session_len = params.session_len;
	data.handle = sev->handle;

	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_START, &data, &argp->error);

	if (!ret && copy_to_user((void __user *)(uintptr_t)params.session_uaddr,
			session_data, params.session_len)) {
		ret = -EFAULT;
		goto e_free_amd_cert;
	}

	params.policy = data.policy;
	params.session_len = data.session_len;
	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params,
				sizeof(struct kvm_sev_send_start)))
		ret = -EFAULT;

e_free_amd_cert:
	kfree(amd_certs);
e_free_plat_cert:
	kfree(plat_certs);
e_free_pdh:
	kfree(pdh_cert);
e_free_session:
	kfree(session_data);
	return ret;
}

/* Userspace wants to query either header or trans length. */
static int
__sev_send_update_data_query_lengths(struct kvm *kvm, struct kvm_sev_cmd *argp,
				     struct kvm_sev_send_update_data *params)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_update_data data;
	int ret;

	memset(&data, 0, sizeof(data));
	data.handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_UPDATE_DATA, &data, &argp->error);

	params->hdr_len = data.hdr_len;
	params->trans_len = data.trans_len;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, params,
			 sizeof(struct kvm_sev_send_update_data)))
		ret = -EFAULT;

	return ret;
}

static int sev_send_update_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_update_data data;
	struct kvm_sev_send_update_data params;
	void *hdr, *trans_data;
	struct page **guest_page;
	unsigned long n;
	int ret, offset;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			sizeof(struct kvm_sev_send_update_data)))
		return -EFAULT;

	/* userspace wants to query either header or trans length */
	if (!params.trans_len || !params.hdr_len)
		return __sev_send_update_data_query_lengths(kvm, argp, &params);

	if (!params.trans_uaddr || !params.guest_uaddr ||
	    !params.guest_len || !params.hdr_uaddr)
		return -EINVAL;

	/* Check if we are crossing the page boundary */
	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	if ((params.guest_len + offset > PAGE_SIZE))
		return -EINVAL;

	/* Pin guest memory */
	guest_page = sev_pin_memory(kvm, params.guest_uaddr & PAGE_MASK,
				    PAGE_SIZE, &n, 0);
	if (!guest_page)
		return -EFAULT;

	/* allocate memory for header and transport buffer */
	ret = -ENOMEM;
	hdr = kmalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr)
		goto e_unpin;

	trans_data = kmalloc(params.trans_len, GFP_KERNEL_ACCOUNT);
	if (!trans_data)
		goto e_free_hdr;

	memset(&data, 0, sizeof(data));
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_address = __psp_pa(trans_data);
	data.trans_len = params.trans_len;

	/* The SEND_UPDATE_DATA command requires C-bit to be always set. */
	data.guest_address = (page_to_pfn(guest_page[0]) << PAGE_SHIFT) + offset;
	data.guest_address |= sev_me_mask;
	data.guest_len = params.guest_len;
	data.handle = sev->handle;

	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_UPDATE_DATA, &data, &argp->error);

	if (ret)
		goto e_free_trans_data;

	/* copy transport buffer to user space */
	if (copy_to_user((void __user *)(uintptr_t)params.trans_uaddr,
			 trans_data, params.trans_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

	/* Copy packet header to userspace. */
	ret = copy_to_user((void __user *)(uintptr_t)params.hdr_uaddr, hdr,
				params.hdr_len);

e_free_trans_data:
	kfree(trans_data);
e_free_hdr:
	kfree(hdr);
e_unpin:
	sev_unpin_memory(kvm, guest_page, n);

	return ret;
}

static int sev_send_finish(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_finish data;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data.handle = sev->handle;
	return sev_issue_cmd(kvm, SEV_CMD_SEND_FINISH, &data, &argp->error);
}

static int sev_send_cancel(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_cancel data;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data.handle = sev->handle;
	return sev_issue_cmd(kvm, SEV_CMD_SEND_CANCEL, &data, &argp->error);
}

static int sev_receive_start(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_receive_start start;
	struct kvm_sev_receive_start params;
	int *error = &argp->error;
	void *session_data;
	void *pdh_data;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	/* Get parameter from the userspace */
	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			sizeof(struct kvm_sev_receive_start)))
		return -EFAULT;

	/* some sanity checks */
	if (!params.pdh_uaddr || !params.pdh_len ||
	    !params.session_uaddr || !params.session_len)
		return -EINVAL;

	pdh_data = psp_copy_user_blob(params.pdh_uaddr, params.pdh_len);
	if (IS_ERR(pdh_data))
		return PTR_ERR(pdh_data);

	session_data = psp_copy_user_blob(params.session_uaddr,
			params.session_len);
	if (IS_ERR(session_data)) {
		ret = PTR_ERR(session_data);
		goto e_free_pdh;
	}

	memset(&start, 0, sizeof(start));
	start.handle = params.handle;
	start.policy = params.policy;
	start.pdh_cert_address = __psp_pa(pdh_data);
	start.pdh_cert_len = params.pdh_len;
	start.session_address = __psp_pa(session_data);
	start.session_len = params.session_len;

	/* create memory encryption context */
	ret = __sev_issue_cmd(argp->sev_fd, SEV_CMD_RECEIVE_START, &start,
				error);
	if (ret)
		goto e_free_session;

	/* Bind ASID to this guest */
	ret = sev_bind_asid(kvm, start.handle, error);
	if (ret)
		goto e_free_session;

	params.handle = start.handle;
	if (copy_to_user((void __user *)(uintptr_t)argp->data,
			 &params, sizeof(struct kvm_sev_receive_start))) {
		ret = -EFAULT;
		sev_unbind_asid(kvm, start.handle);
		goto e_free_session;
	}

    	sev->handle = start.handle;
	sev->fd = argp->sev_fd;

e_free_session:
	kfree(session_data);
e_free_pdh:
	kfree(pdh_data);

	return ret;
}

static int sev_receive_update_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_receive_update_data params;
	struct sev_data_receive_update_data data;
	void *hdr = NULL, *trans = NULL;
	struct page **guest_page;
	unsigned long n;
	int ret, offset;

	if (!sev_guest(kvm))
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			sizeof(struct kvm_sev_receive_update_data)))
		return -EFAULT;

	if (!params.hdr_uaddr || !params.hdr_len ||
	    !params.guest_uaddr || !params.guest_len ||
	    !params.trans_uaddr || !params.trans_len)
		return -EINVAL;

	/* Check if we are crossing the page boundary */
	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	if ((params.guest_len + offset > PAGE_SIZE))
		return -EINVAL;

	hdr = psp_copy_user_blob(params.hdr_uaddr, params.hdr_len);
	if (IS_ERR(hdr))
		return PTR_ERR(hdr);

	trans = psp_copy_user_blob(params.trans_uaddr, params.trans_len);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto e_free_hdr;
	}

	memset(&data, 0, sizeof(data));
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_address = __psp_pa(trans);
	data.trans_len = params.trans_len;

	/* Pin guest memory */
	ret = -EFAULT;
	guest_page = sev_pin_memory(kvm, params.guest_uaddr & PAGE_MASK,
				    PAGE_SIZE, &n, 0);
	if (!guest_page)
		goto e_free_trans;

	/* The RECEIVE_UPDATE_DATA command requires C-bit to be always set. */
	data.guest_address = (page_to_pfn(guest_page[0]) << PAGE_SHIFT) + offset;
	data.guest_address |= sev_me_mask;
	data.guest_len = params.guest_len;
	data.handle = sev->handle;

	ret = sev_issue_cmd(kvm, SEV_CMD_RECEIVE_UPDATE_DATA, &data,
				&argp->error);

	sev_unpin_memory(kvm, guest_page, n);

e_free_trans:
	kfree(trans);
e_free_hdr:
	kfree(hdr);

	return ret;
}

static int sev_receive_finish(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_receive_finish data;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data.handle = sev->handle;
	return sev_issue_cmd(kvm, SEV_CMD_RECEIVE_FINISH, &data, &argp->error);
}

static void *snp_context_create(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_gctx_create data = {};
	void *context;
	int rc;

	/* Allocate memory for context page */
	context = snp_alloc_firmware_page(GFP_KERNEL_ACCOUNT);
	if (!context)
		return NULL;

	/* Allocate a firmware buffer used during the guest command handling. */
	sev->snp_resp_page = snp_alloc_firmware_page(GFP_KERNEL_ACCOUNT);
	if (!sev->snp_resp_page) {
		snp_free_firmware_page(context);
		return NULL;
	}

	data.gctx_paddr = __psp_pa(context);
	rc = __sev_issue_cmd(argp->sev_fd, SEV_CMD_SNP_GCTX_CREATE, &data, &argp->error);
	if (rc)
		goto e_free;

	return context;

e_free:
	snp_free_firmware_page(context);
	snp_free_firmware_page(sev->snp_resp_page);
	return NULL;
}

static int snp_bind_asid(struct kvm *kvm, int *error)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_activate data = {};
	int asid = sev_get_asid(kvm);
	int ret, retry_count = 0;

	/* Activate ASID on the given context */
	data.gctx_paddr = __psp_pa(sev->snp_context);
	data.asid   = asid;
again:
	ret = sev_issue_cmd(kvm, SEV_CMD_SNP_ACTIVATE, &data, error);

	/* Check if the DF_FLUSH is required, and try again */
	if (ret && (*error == SEV_RET_DFFLUSH_REQUIRED) && (!retry_count)) {
		/* Guard DEACTIVATE against WBINVD/DF_FLUSH used in ASID recycling */
		down_read(&sev_deactivate_lock);
		wbinvd_on_all_cpus();
		ret = snp_guest_df_flush(error);
		up_read(&sev_deactivate_lock);

		if (ret)
			return ret;

		/* only one retry */
		retry_count = 1;

		goto again;
	}

	return ret;
}

static int snp_launch_start(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_launch_start start = {};
	struct kvm_sev_snp_launch_start params;
	int rc;

	if (!sev_snp_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	/* Initialize the guest context */
	sev->snp_context = snp_context_create(kvm, argp);
	if (!sev->snp_context)
		return -ENOTTY;

	/* Issue the LAUNCH_START command */
	start.gctx_paddr = __psp_pa(sev->snp_context);
	start.policy = params.policy;
	memcpy(start.gosvw, params.gosvw, sizeof(params.gosvw));
	rc = __sev_issue_cmd(argp->sev_fd, SEV_CMD_SNP_LAUNCH_START, &start, &argp->error);
	if (rc)
		goto e_free_context;

	/* Bind ASID to this guest */
	sev->fd = argp->sev_fd;
	rc = snp_bind_asid(kvm, &argp->error);
	if (rc)
		goto e_free_context;

	/* Used for rate limiting SNP guest message request, use the default settings */
	ratelimit_default_init(&sev->snp_guest_msg_rs);

	/* Allocate memory used for the certs data in SNP guest request */
	sev->snp_certs_data = kmalloc(SEV_FW_BLOB_MAX_SIZE, GFP_KERNEL_ACCOUNT);

	return 0;

e_free_context:
	snp_decommission_context(kvm);

	return rc;
}

static struct kvm_memory_slot *hva_to_memslot(struct kvm *kvm, unsigned long hva)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	struct kvm_memory_slot *memslot;

	kvm_for_each_memslot(memslot, slots) {
		if (hva >= memslot->userspace_addr &&
		    hva < memslot->userspace_addr + (memslot->npages << PAGE_SHIFT))
			return memslot;
	}

	return NULL;
}

static bool hva_to_gpa(struct kvm *kvm, unsigned long hva, gpa_t *gpa)
{
	struct kvm_memory_slot *memslot;
	gpa_t gpa_offset;

	memslot = hva_to_memslot(kvm, hva);
	if (!memslot)
		return false;

	gpa_offset = hva - memslot->userspace_addr;
	*gpa = ((memslot->base_gfn << PAGE_SHIFT) + gpa_offset);

	return true;
}

static int snp_page_reclaim(struct page *page, int rmppage_size)
{
	struct sev_data_snp_page_reclaim data = {};
	struct rmpupdate e = {};
	int rc, err;

	data.paddr = __sme_page_pa(page) | rmppage_size;
	rc = snp_guest_page_reclaim(&data, &err);
	if (rc)
		return rc;

	return rmpupdate(page, &e);
}

static int snp_launch_update(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	unsigned long npages, vaddr, vaddr_end, i, next_vaddr;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_launch_update data = {};
	struct kvm_sev_snp_launch_update params;
	int *error = &argp->error;
	struct kvm_vcpu *vcpu;
	struct page **inpages;
	struct rmpupdate e;
	int ret;

	if (!sev_snp_guest(kvm))
		return -ENOTTY;

	if (!sev->snp_context)
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	data.gctx_paddr = __psp_pa(sev->snp_context);

	/* Lock the user memory. */
	inpages = sev_pin_memory(kvm, params.uaddr, params.len, &npages, 1);
	if (!inpages)
		return -ENOMEM;

	vcpu = kvm_get_vcpu(kvm, 0);
	vaddr = params.uaddr;
	vaddr_end = vaddr + params.len;

	for (i = 0; vaddr < vaddr_end; vaddr = next_vaddr, i++) {
		unsigned long psize, pmask;
		int level = PG_LEVEL_4K;
		gpa_t gpa;

		if (!hva_to_gpa(kvm, vaddr, &gpa)) {
			ret = -EINVAL;
			goto e_unpin;
		}

		psize = page_level_size(level);
		pmask = page_level_mask(level);
		gpa = gpa & pmask;

		/* Transition the page state to pre-guest */
		memset(&e, 0, sizeof(e));
		e.assigned = 1;
		e.gpa = gpa;
		e.asid = sev_get_asid(kvm);
		e.immutable = true;
		e.pagesize = X86_TO_RMP_PG_LEVEL(level);
		ret = rmpupdate(inpages[i], &e);
		if (ret) {
			ret = -EFAULT;
			goto e_unpin;
		}

		data.address = __sme_page_pa(inpages[i]);
		data.page_size = e.pagesize;
		data.page_type = params.page_type;
		data.vmpl3_perms = params.vmpl3_perms;
		data.vmpl2_perms = params.vmpl2_perms;
		data.vmpl1_perms = params.vmpl1_perms;
		ret = __sev_issue_cmd(argp->sev_fd, SEV_CMD_SNP_LAUNCH_UPDATE, &data, error);
		if (ret) {
			snp_page_reclaim(inpages[i], e.pagesize);
			goto e_unpin;
		}

		next_vaddr = (vaddr & pmask) + psize;
	}

e_unpin:
	/* Content of memory is updated, mark pages dirty */
	memset(&e, 0, sizeof(e));
	for (i = 0; i < npages; i++) {
		set_page_dirty_lock(inpages[i]);
		mark_page_accessed(inpages[i]);

		/*
		 * If its an error, then update RMP entry to change page ownership
		 * to the hypervisor.
		 */
		if (ret)
			rmpupdate(inpages[i], &e);
	}

	/* Unlock the user pages */
	sev_unpin_memory(kvm, inpages, npages);

	return ret;
}

static int snp_launch_update_vmsa(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_launch_update data = {};
	int i, ret;

	data.gctx_paddr = __psp_pa(sev->snp_context);
	data.page_type = SNP_PAGE_TYPE_VMSA;

	for (i = 0; i < kvm->created_vcpus; i++) {
		struct vcpu_svm *svm = to_svm(kvm->vcpus[i]);
		struct rmpupdate e = {};

		/* Perform some pre-encryption checks against the VMSA */
		ret = sev_es_sync_vmsa(svm);
		if (ret)
			return ret;

		/* Transition the VMSA page to a firmware state. */
		e.assigned = 1;
		e.immutable = 1;
		e.asid = sev->asid;
		e.gpa = -1;
		e.pagesize = RMP_PG_SIZE_4K;
		ret = rmpupdate(virt_to_page(svm->vmsa), &e);
		if (ret)
			return ret;

		/* Issue the SNP command to encrypt the VMSA */
		data.address = __sme_pa(svm->vmsa);
		ret = __sev_issue_cmd(argp->sev_fd, SEV_CMD_SNP_LAUNCH_UPDATE,
				      &data, &argp->error);
		if (ret) {
			snp_page_reclaim(virt_to_page(svm->vmsa), RMP_PG_SIZE_4K);
			return ret;
		}

		svm->vcpu.arch.guest_state_protected = true;
	}

	return 0;
}

static int snp_launch_finish(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_launch_finish *data;
	void *id_block = NULL, *id_auth = NULL;
	struct kvm_sev_snp_launch_finish params;
	int ret;

	if (!sev_snp_guest(kvm))
		return -ENOTTY;

	if (!sev->snp_context)
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	/* Measure all vCPUs using LAUNCH_UPDATE before we finalize the launch flow. */
	ret = snp_launch_update_vmsa(kvm, argp);
	if (ret)
		return ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	if (params.id_block_en) {
		id_block = psp_copy_user_blob(params.id_block_uaddr, KVM_SEV_SNP_ID_BLOCK_SIZE);
		if (IS_ERR(id_block)) {
			ret = PTR_ERR(id_block);
			goto e_free;
		}

		data->id_block_en = 1;
		data->id_block_paddr = __sme_pa(id_block);
	}

	if (params.auth_key_en) {
		id_auth = psp_copy_user_blob(params.id_auth_uaddr, KVM_SEV_SNP_ID_AUTH_SIZE);
		if (IS_ERR(id_auth)) {
			ret = PTR_ERR(id_auth);
			goto e_free_id_block;
		}

		data->auth_key_en = 1;
		data->id_auth_paddr = __sme_pa(id_auth);
	}

	data->gctx_paddr = __psp_pa(sev->snp_context);
	ret = sev_issue_cmd(kvm, SEV_CMD_SNP_LAUNCH_FINISH, data, &argp->error);

	kfree(id_auth);

e_free_id_block:
	kfree(id_block);

e_free:
	kfree(data);

	return ret;
}

int svm_mem_enc_op(struct kvm *kvm, void __user *argp)
{
	struct kvm_sev_cmd sev_cmd;
	int r;

	if (!sev_enabled)
		return -ENOTTY;

	if (!argp)
		return 0;

	if (copy_from_user(&sev_cmd, argp, sizeof(struct kvm_sev_cmd)))
		return -EFAULT;

	mutex_lock(&kvm->lock);

	/* enc_context_owner handles all memory enc operations */
	if (is_mirroring_enc_context(kvm)) {
		r = -EINVAL;
		goto out;
	}

	switch (sev_cmd.id) {
	case KVM_SEV_SNP_INIT:
		if (!sev_snp_enabled) {
			r = -ENOTTY;
			goto out;
		}
		fallthrough;
	case KVM_SEV_ES_INIT:
		if (!sev_es_enabled) {
			r = -ENOTTY;
			goto out;
		}
		fallthrough;
	case KVM_SEV_INIT:
		r = sev_guest_init(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_START:
		r = sev_launch_start(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_UPDATE_DATA:
		r = sev_launch_update_data(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_UPDATE_VMSA:
		r = sev_launch_update_vmsa(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_MEASURE:
		r = sev_launch_measure(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_FINISH:
		r = sev_launch_finish(kvm, &sev_cmd);
		break;
	case KVM_SEV_GUEST_STATUS:
		r = sev_guest_status(kvm, &sev_cmd);
		break;
	case KVM_SEV_DBG_DECRYPT:
		r = sev_dbg_crypt(kvm, &sev_cmd, true);
		break;
	case KVM_SEV_DBG_ENCRYPT:
		r = sev_dbg_crypt(kvm, &sev_cmd, false);
		break;
	case KVM_SEV_LAUNCH_SECRET:
		r = sev_launch_secret(kvm, &sev_cmd);
		break;
	case KVM_SEV_GET_ATTESTATION_REPORT:
		r = sev_get_attestation_report(kvm, &sev_cmd);
		break;
	case KVM_SEV_SEND_START:
		r = sev_send_start(kvm, &sev_cmd);
		break;
	case KVM_SEV_SEND_UPDATE_DATA:
		r = sev_send_update_data(kvm, &sev_cmd);
		break;
	case KVM_SEV_SEND_FINISH:
		r = sev_send_finish(kvm, &sev_cmd);
		break;
	case KVM_SEV_SEND_CANCEL:
		r = sev_send_cancel(kvm, &sev_cmd);
		break;
	case KVM_SEV_RECEIVE_START:
		r = sev_receive_start(kvm, &sev_cmd);
		break;
	case KVM_SEV_RECEIVE_UPDATE_DATA:
		r = sev_receive_update_data(kvm, &sev_cmd);
		break;
	case KVM_SEV_RECEIVE_FINISH:
		r = sev_receive_finish(kvm, &sev_cmd);
		break;
	case KVM_SEV_SNP_LAUNCH_START:
		r = snp_launch_start(kvm, &sev_cmd);
		break;
	case KVM_SEV_SNP_LAUNCH_UPDATE:
		r = snp_launch_update(kvm, &sev_cmd);
		break;
	case KVM_SEV_SNP_LAUNCH_FINISH:
		r = snp_launch_finish(kvm, &sev_cmd);
		break;
	default:
		r = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &sev_cmd, sizeof(struct kvm_sev_cmd)))
		r = -EFAULT;

out:
	mutex_unlock(&kvm->lock);
	return r;
}

int svm_register_enc_region(struct kvm *kvm,
			    struct kvm_enc_region *range)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct enc_region *region;
	int ret = 0;

	if (!sev_guest(kvm))
		return -ENOTTY;

	/* If kvm is mirroring encryption context it isn't responsible for it */
	if (is_mirroring_enc_context(kvm))
		return -EINVAL;

	if (range->addr > ULONG_MAX || range->size > ULONG_MAX)
		return -EINVAL;

	region = kzalloc(sizeof(*region), GFP_KERNEL_ACCOUNT);
	if (!region)
		return -ENOMEM;

	mutex_lock(&kvm->lock);
	region->pages = sev_pin_memory(kvm, range->addr, range->size, &region->npages, 1);
	if (IS_ERR(region->pages)) {
		ret = PTR_ERR(region->pages);
		mutex_unlock(&kvm->lock);
		goto e_free;
	}

	region->uaddr = range->addr;
	region->size = range->size;

	list_add_tail(&region->list, &sev->regions_list);
	mutex_unlock(&kvm->lock);

	/*
	 * The guest may change the memory encryption attribute from C=0 -> C=1
	 * or vice versa for this memory range. Lets make sure caches are
	 * flushed to ensure that guest data gets written into memory with
	 * correct C-bit.
	 */
	sev_clflush_pages(region->pages, region->npages);

	return ret;

e_free:
	kfree(region);
	return ret;
}

static struct enc_region *
find_enc_region(struct kvm *kvm, struct kvm_enc_region *range)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct list_head *head = &sev->regions_list;
	struct enc_region *i;

	list_for_each_entry(i, head, list) {
		if (i->uaddr == range->addr &&
		    i->size == range->size)
			return i;
	}

	return NULL;
}

static void __unregister_enc_region_locked(struct kvm *kvm,
					   struct enc_region *region)
{
	struct rmpupdate val = {};
	unsigned long i, pfn;
	struct rmpentry *e;
	int level, rc;

	/*
	 * The guest memory pages are assigned in the RMP table. Unassign it
	 * before releasing the memory.
	 */
	if (sev_snp_guest(kvm)) {
		for (i = 0; i < region->npages; i++) {
			pfn = page_to_pfn(region->pages[i]);

			if (need_resched())
				schedule();

			e = snp_lookup_page_in_rmptable(region->pages[i], &level);
			if (unlikely(!e))
				continue;

			/* If its not a guest assigned page then skip it. */
			if (!rmpentry_assigned(e))
				continue;

			/* Is the page part of a 2MB RMP entry? */
			if (level == PG_LEVEL_2M) {
				val.pagesize = RMP_PG_SIZE_2M;
				pfn &= ~(KVM_PAGES_PER_HPAGE(PG_LEVEL_2M) - 1);
			} else {
				val.pagesize = RMP_PG_SIZE_4K;
			}

			/* Transition the page to hypervisor owned. */
			rc = rmpupdate(pfn_to_page(pfn), &val);
			if (rc)
				pr_err("Failed to release pfn 0x%lx ret=%d\n", pfn, rc);
		}
	}

	sev_unpin_memory(kvm, region->pages, region->npages);
	list_del(&region->list);
	kfree(region);
}

int svm_unregister_enc_region(struct kvm *kvm,
			      struct kvm_enc_region *range)
{
	struct enc_region *region;
	int ret;

	/* If kvm is mirroring encryption context it isn't responsible for it */
	if (is_mirroring_enc_context(kvm))
		return -EINVAL;

	mutex_lock(&kvm->lock);

	if (!sev_guest(kvm)) {
		ret = -ENOTTY;
		goto failed;
	}

	region = find_enc_region(kvm, range);
	if (!region) {
		ret = -EINVAL;
		goto failed;
	}

	/*
	 * Ensure that all guest tagged cache entries are flushed before
	 * releasing the pages back to the system for use. CLFLUSH will
	 * not do this, so issue a WBINVD.
	 */
	wbinvd_on_all_cpus();

	__unregister_enc_region_locked(kvm, region);

	mutex_unlock(&kvm->lock);
	return 0;

failed:
	mutex_unlock(&kvm->lock);
	return ret;
}

int svm_vm_copy_asid_from(struct kvm *kvm, unsigned int source_fd)
{
	struct file *source_kvm_file;
	struct kvm *source_kvm;
	struct kvm_sev_info *mirror_sev;
	unsigned int asid;
	int ret;

	source_kvm_file = fget(source_fd);
	if (!file_is_kvm(source_kvm_file)) {
		ret = -EBADF;
		goto e_source_put;
	}

	source_kvm = source_kvm_file->private_data;
	mutex_lock(&source_kvm->lock);

	if (!sev_guest(source_kvm)) {
		ret = -EINVAL;
		goto e_source_unlock;
	}

	/* Mirrors of mirrors should work, but let's not get silly */
	if (is_mirroring_enc_context(source_kvm) || source_kvm == kvm) {
		ret = -EINVAL;
		goto e_source_unlock;
	}

	asid = to_kvm_svm(source_kvm)->sev_info.asid;

	/*
	 * The mirror kvm holds an enc_context_owner ref so its asid can't
	 * disappear until we're done with it
	 */
	kvm_get_kvm(source_kvm);

	fput(source_kvm_file);
	mutex_unlock(&source_kvm->lock);
	mutex_lock(&kvm->lock);

	if (sev_guest(kvm)) {
		ret = -EINVAL;
		goto e_mirror_unlock;
	}

	/* Set enc_context_owner and copy its encryption context over */
	mirror_sev = &to_kvm_svm(kvm)->sev_info;
	mirror_sev->enc_context_owner = source_kvm;
	mirror_sev->asid = asid;
	mirror_sev->active = true;

	mutex_unlock(&kvm->lock);
	return 0;

e_mirror_unlock:
	mutex_unlock(&kvm->lock);
	kvm_put_kvm(source_kvm);
	return ret;
e_source_unlock:
	mutex_unlock(&source_kvm->lock);
e_source_put:
	if (source_kvm_file)
		fput(source_kvm_file);
	return ret;
}

static int snp_decommission_context(struct kvm *kvm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_decommission data = {};
	int ret;

	/* If context is not created then do nothing */
	if (!sev->snp_context)
		return 0;

	data.gctx_paddr = __sme_pa(sev->snp_context);
	ret = snp_guest_decommission(&data, NULL);
	if (ret)
		return ret;

	/* free the context page now */
	snp_free_firmware_page(sev->snp_context);
	sev->snp_context = NULL;

	/* Free the response page. */
	snp_free_firmware_page(sev->snp_resp_page);

	return 0;
}

void sev_vm_destroy(struct kvm *kvm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct list_head *head = &sev->regions_list;
	struct list_head *pos, *q;

	if (!sev_guest(kvm))
		return;

	/* If this is a mirror_kvm release the enc_context_owner and skip sev cleanup */
	if (is_mirroring_enc_context(kvm)) {
		kvm_put_kvm(sev->enc_context_owner);
		return;
	}

	mutex_lock(&kvm->lock);

	/*
	 * Ensure that all guest tagged cache entries are flushed before
	 * releasing the pages back to the system for use. CLFLUSH will
	 * not do this, so issue a WBINVD.
	 */
	wbinvd_on_all_cpus();

	/*
	 * if userspace was terminated before unregistering the memory regions
	 * then lets unpin all the registered memory.
	 */
	if (!list_empty(head)) {
		list_for_each_safe(pos, q, head) {
			__unregister_enc_region_locked(kvm,
				list_entry(pos, struct enc_region, list));
			cond_resched();
		}
	}

	mutex_unlock(&kvm->lock);

	if (sev_snp_guest(kvm)) {
		if (snp_decommission_context(kvm)) {
			pr_err("Failed to free SNP guest context, leaking asid!\n");
			return;
		}
	} else {
		sev_unbind_asid(kvm, sev->handle);
	}


	kfree(sev->snp_certs_data);

	sev_asid_free(sev);
}

void __init sev_set_cpu_caps(void)
{
	if (!sev_enabled)
		kvm_cpu_cap_clear(X86_FEATURE_SEV);
	if (!sev_es_enabled)
		kvm_cpu_cap_clear(X86_FEATURE_SEV_ES);
}

void __init sev_hardware_setup(void)
{
#ifdef CONFIG_KVM_AMD_SEV
	unsigned int eax, ebx, ecx, edx, sev_asid_count, sev_es_asid_count;
	bool sev_snp_supported = false;
	bool sev_es_supported = false;
	bool sev_supported = false;

	if (!sev_enabled || !npt_enabled)
		goto out;

	/* Does the CPU support SEV? */
	if (!boot_cpu_has(X86_FEATURE_SEV))
		goto out;

	/* Retrieve SEV CPUID information */
	cpuid(0x8000001f, &eax, &ebx, &ecx, &edx);

	/* Set encryption bit location for SEV-ES guests */
	sev_enc_bit = ebx & 0x3f;

	/* Maximum number of encrypted guests supported simultaneously */
	max_sev_asid = ecx;
	if (!max_sev_asid)
		goto out;

	/* Minimum ASID value that should be used for SEV guest */
	min_sev_asid = edx;
	sev_me_mask = 1UL << (ebx & 0x3f);

	/* Initialize SEV ASID bitmaps */
	sev_asid_bitmap = bitmap_zalloc(max_sev_asid, GFP_KERNEL);
	if (!sev_asid_bitmap)
		goto out;

	sev_reclaim_asid_bitmap = bitmap_zalloc(max_sev_asid, GFP_KERNEL);
	if (!sev_reclaim_asid_bitmap) {
		bitmap_free(sev_asid_bitmap);
		sev_asid_bitmap = NULL;
		goto out;
	}

	sev_asid_count = max_sev_asid - min_sev_asid + 1;
	if (misc_cg_set_capacity(MISC_CG_RES_SEV, sev_asid_count))
		goto out;

	pr_info("SEV supported: %u ASIDs\n", sev_asid_count);
	sev_supported = true;

	/* SEV-ES support requested? */
	if (!sev_es_enabled)
		goto out;

	/* Does the CPU support SEV-ES? */
	if (!boot_cpu_has(X86_FEATURE_SEV_ES))
		goto out;

	/* Has the system been allocated ASIDs for SEV-ES? */
	if (min_sev_asid == 1)
		goto out;

	sev_es_asid_count = min_sev_asid - 1;
	if (misc_cg_set_capacity(MISC_CG_RES_SEV_ES, sev_es_asid_count))
		goto out;

	pr_info("SEV-ES supported: %u ASIDs\n", sev_es_asid_count);
	sev_es_supported = true;

	/* SEV-SNP support requested? */
	if (!sev_snp_enabled)
		goto out;

	/* Is SEV-SNP enabled? */
	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		goto out;

	pr_info("SEV-SNP supported: %u ASIDs\n", min_sev_asid - 1);
	sev_snp_supported = true;

out:
	sev_enabled = sev_supported;
	sev_es_enabled = sev_es_supported;
	sev_snp_enabled = sev_snp_supported;
#endif
}

void sev_hardware_teardown(void)
{
	if (!sev_enabled)
		return;

	/* No need to take sev_bitmap_lock, all VMs have been destroyed. */
	sev_flush_asids(0, max_sev_asid);

	bitmap_free(sev_asid_bitmap);
	bitmap_free(sev_reclaim_asid_bitmap);

	misc_cg_set_capacity(MISC_CG_RES_SEV, 0);
	misc_cg_set_capacity(MISC_CG_RES_SEV_ES, 0);
}

int sev_cpu_init(struct svm_cpu_data *sd)
{
	if (!sev_enabled)
		return 0;

	sd->sev_vmcbs = kcalloc(max_sev_asid + 1, sizeof(void *), GFP_KERNEL);
	if (!sd->sev_vmcbs)
		return -ENOMEM;

	return 0;
}

/*
 * Pages used by hardware to hold guest encrypted state must be flushed before
 * returning them to the system.
 */
static void sev_flush_guest_memory(struct vcpu_svm *svm, void *va,
				   unsigned long len)
{
	/*
	 * If hardware enforced cache coherency for encrypted mappings of the
	 * same physical page is supported, nothing to do.
	 */
	if (boot_cpu_has(X86_FEATURE_SME_COHERENT))
		return;

	/*
	 * If the VM Page Flush MSR is supported, use it to flush the page
	 * (using the page virtual address and the guest ASID).
	 */
	if (boot_cpu_has(X86_FEATURE_VM_PAGE_FLUSH)) {
		struct kvm_sev_info *sev;
		unsigned long va_start;
		u64 start, stop;

		/* Align start and stop to page boundaries. */
		va_start = (unsigned long)va;
		start = (u64)va_start & PAGE_MASK;
		stop = PAGE_ALIGN((u64)va_start + len);

		if (start < stop) {
			sev = &to_kvm_svm(svm->vcpu.kvm)->sev_info;

			while (start < stop) {
				wrmsrl(MSR_AMD64_VM_PAGE_FLUSH,
				       start | sev->asid);

				start += PAGE_SIZE;
			}

			return;
		}

		WARN(1, "Address overflow, using WBINVD\n");
	}

	/*
	 * Hardware should always have one of the above features,
	 * but if not, use WBINVD and issue a warning.
	 */
	WARN_ONCE(1, "Using WBINVD to flush guest memory\n");
	wbinvd_on_all_cpus();
}

void sev_free_vcpu(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm;

	if (!sev_es_guest(vcpu->kvm))
		return;

	svm = to_svm(vcpu);

	if (vcpu->arch.guest_state_protected)
		sev_flush_guest_memory(svm, svm->vmsa, PAGE_SIZE);

	/*
	 * If its an SNP guest, then VMSA was added in the RMP entry as a guest owned page.
	 * Transition the page to hyperivosr state before releasing it back to the system.
	 */
	if (sev_snp_guest(vcpu->kvm)) {
		struct rmpupdate e = {};
		int rc;

		rc = rmpupdate(virt_to_page(svm->vmsa), &e);
		if (rc) {
			pr_err("Failed to release SNP guest VMSA page (rc %d), leaking it\n", rc);
			goto skip_vmsa_free;
		}
	}

	__free_page(virt_to_page(svm->vmsa));

skip_vmsa_free:
	if (svm->ghcb_sa_free)
		kfree(svm->ghcb_sa);
}

static void dump_ghcb(struct vcpu_svm *svm)
{
	struct ghcb *ghcb = svm->ghcb;
	unsigned int nbits;

	/* Re-use the dump_invalid_vmcb module parameter */
	if (!dump_invalid_vmcb) {
		pr_warn_ratelimited("set kvm_amd.dump_invalid_vmcb=1 to dump internal KVM state.\n");
		return;
	}

	nbits = sizeof(ghcb->save.valid_bitmap) * 8;

	pr_err("GHCB (GPA=%016llx):\n", svm->vmcb->control.ghcb_gpa);
	pr_err("%-20s%016llx is_valid: %u\n", "sw_exit_code",
	       ghcb->save.sw_exit_code, ghcb_sw_exit_code_is_valid(ghcb));
	pr_err("%-20s%016llx is_valid: %u\n", "sw_exit_info_1",
	       ghcb->save.sw_exit_info_1, ghcb_sw_exit_info_1_is_valid(ghcb));
	pr_err("%-20s%016llx is_valid: %u\n", "sw_exit_info_2",
	       ghcb->save.sw_exit_info_2, ghcb_sw_exit_info_2_is_valid(ghcb));
	pr_err("%-20s%016llx is_valid: %u\n", "sw_scratch",
	       ghcb->save.sw_scratch, ghcb_sw_scratch_is_valid(ghcb));
	pr_err("%-20s%*pb\n", "valid_bitmap", nbits, ghcb->save.valid_bitmap);
}

static void sev_es_sync_to_ghcb(struct vcpu_svm *svm)
{
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct ghcb *ghcb = svm->ghcb;

	/*
	 * The GHCB protocol so far allows for the following data
	 * to be returned:
	 *   GPRs RAX, RBX, RCX, RDX
	 *
	 * Copy their values, even if they may not have been written during the
	 * VM-Exit.  It's the guest's responsibility to not consume random data.
	 */
	ghcb_set_rax(ghcb, vcpu->arch.regs[VCPU_REGS_RAX]);
	ghcb_set_rbx(ghcb, vcpu->arch.regs[VCPU_REGS_RBX]);
	ghcb_set_rcx(ghcb, vcpu->arch.regs[VCPU_REGS_RCX]);
	ghcb_set_rdx(ghcb, vcpu->arch.regs[VCPU_REGS_RDX]);
}

static void sev_es_sync_from_ghcb(struct vcpu_svm *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct ghcb *ghcb = svm->ghcb;
	u64 exit_code;

	/*
	 * The GHCB protocol so far allows for the following data
	 * to be supplied:
	 *   GPRs RAX, RBX, RCX, RDX
	 *   XCR0
	 *   CPL
	 *
	 * VMMCALL allows the guest to provide extra registers. KVM also
	 * expects RSI for hypercalls, so include that, too.
	 *
	 * Copy their values to the appropriate location if supplied.
	 */
	memset(vcpu->arch.regs, 0, sizeof(vcpu->arch.regs));

	vcpu->arch.regs[VCPU_REGS_RAX] = ghcb_get_rax_if_valid(ghcb);
	vcpu->arch.regs[VCPU_REGS_RBX] = ghcb_get_rbx_if_valid(ghcb);
	vcpu->arch.regs[VCPU_REGS_RCX] = ghcb_get_rcx_if_valid(ghcb);
	vcpu->arch.regs[VCPU_REGS_RDX] = ghcb_get_rdx_if_valid(ghcb);
	vcpu->arch.regs[VCPU_REGS_RSI] = ghcb_get_rsi_if_valid(ghcb);

	svm->vmcb->save.cpl = ghcb_get_cpl_if_valid(ghcb);

	if (ghcb_xcr0_is_valid(ghcb)) {
		vcpu->arch.xcr0 = ghcb_get_xcr0(ghcb);
		kvm_update_cpuid_runtime(vcpu);
	}

	/* Copy the GHCB exit information into the VMCB fields */
	exit_code = ghcb_get_sw_exit_code(ghcb);
	control->exit_code = lower_32_bits(exit_code);
	control->exit_code_hi = upper_32_bits(exit_code);
	control->exit_info_1 = ghcb_get_sw_exit_info_1(ghcb);
	control->exit_info_2 = ghcb_get_sw_exit_info_2(ghcb);

	/* Clear the valid entries fields */
	memset(ghcb->save.valid_bitmap, 0, sizeof(ghcb->save.valid_bitmap));
}

static int sev_es_validate_vmgexit(struct vcpu_svm *svm)
{
	struct kvm_vcpu *vcpu;
	struct ghcb *ghcb;
	u64 exit_code = 0;

	ghcb = svm->ghcb;

	/* Only GHCB Usage code 0 is supported */
	if (ghcb->ghcb_usage)
		goto vmgexit_err;

	/*
	 * Retrieve the exit code now even though is may not be marked valid
	 * as it could help with debugging.
	 */
	exit_code = ghcb_get_sw_exit_code(ghcb);

	if (!ghcb_sw_exit_code_is_valid(ghcb) ||
	    !ghcb_sw_exit_info_1_is_valid(ghcb) ||
	    !ghcb_sw_exit_info_2_is_valid(ghcb))
		goto vmgexit_err;

	switch (ghcb_get_sw_exit_code(ghcb)) {
	case SVM_EXIT_READ_DR7:
		break;
	case SVM_EXIT_WRITE_DR7:
		if (!ghcb_rax_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_EXIT_RDTSC:
		break;
	case SVM_EXIT_RDPMC:
		if (!ghcb_rcx_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_EXIT_CPUID:
		if (!ghcb_rax_is_valid(ghcb) ||
		    !ghcb_rcx_is_valid(ghcb))
			goto vmgexit_err;
		if (ghcb_get_rax(ghcb) == 0xd)
			if (!ghcb_xcr0_is_valid(ghcb))
				goto vmgexit_err;
		break;
	case SVM_EXIT_INVD:
		break;
	case SVM_EXIT_IOIO:
		if (ghcb_get_sw_exit_info_1(ghcb) & SVM_IOIO_STR_MASK) {
			if (!ghcb_sw_scratch_is_valid(ghcb))
				goto vmgexit_err;
		} else {
			if (!(ghcb_get_sw_exit_info_1(ghcb) & SVM_IOIO_TYPE_MASK))
				if (!ghcb_rax_is_valid(ghcb))
					goto vmgexit_err;
		}
		break;
	case SVM_EXIT_MSR:
		if (!ghcb_rcx_is_valid(ghcb))
			goto vmgexit_err;
		if (ghcb_get_sw_exit_info_1(ghcb)) {
			if (!ghcb_rax_is_valid(ghcb) ||
			    !ghcb_rdx_is_valid(ghcb))
				goto vmgexit_err;
		}
		break;
	case SVM_EXIT_VMMCALL:
		if (!ghcb_rax_is_valid(ghcb) ||
		    !ghcb_cpl_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_EXIT_RDTSCP:
		break;
	case SVM_EXIT_WBINVD:
		break;
	case SVM_EXIT_MONITOR:
		if (!ghcb_rax_is_valid(ghcb) ||
		    !ghcb_rcx_is_valid(ghcb) ||
		    !ghcb_rdx_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_EXIT_MWAIT:
		if (!ghcb_rax_is_valid(ghcb) ||
		    !ghcb_rcx_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_VMGEXIT_MMIO_READ:
	case SVM_VMGEXIT_MMIO_WRITE:
		if (!ghcb_sw_scratch_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_VMGEXIT_AP_CREATION:
		if (!ghcb_rax_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_VMGEXIT_NMI_COMPLETE:
	case SVM_VMGEXIT_AP_HLT_LOOP:
	case SVM_VMGEXIT_AP_JUMP_TABLE:
	case SVM_VMGEXIT_UNSUPPORTED_EVENT:
	case SVM_VMGEXIT_HV_FT:
	case SVM_VMGEXIT_PSC:
	case SVM_VMGEXIT_GUEST_REQUEST:
	case SVM_VMGEXIT_EXT_GUEST_REQUEST:
		break;
	default:
		goto vmgexit_err;
	}

	return 0;

vmgexit_err:
	vcpu = &svm->vcpu;

	if (ghcb->ghcb_usage) {
		vcpu_unimpl(vcpu, "vmgexit: ghcb usage %#x is not valid\n",
			    ghcb->ghcb_usage);
	} else {
		vcpu_unimpl(vcpu, "vmgexit: exit reason %#llx is not valid\n",
			    exit_code);
		dump_ghcb(svm);
	}

	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON;
	vcpu->run->internal.ndata = 2;
	vcpu->run->internal.data[0] = exit_code;
	vcpu->run->internal.data[1] = vcpu->arch.last_vmentry_cpu;

	return -EINVAL;
}

void sev_es_unmap_ghcb(struct vcpu_svm *svm)
{
	/* Clear any indication that the vCPU is in a type of AP Reset Hold */
	svm->ap_reset_hold_type = AP_RESET_HOLD_NONE;

	if (!svm->ghcb)
		return;

	if (svm->ghcb_sa_free) {
		/*
		 * The scratch area lives outside the GHCB, so there is a
		 * buffer that, depending on the operation performed, may
		 * need to be synced, then freed.
		 */
		if (svm->ghcb_sa_sync) {
			kvm_write_guest(svm->vcpu.kvm,
					ghcb_get_sw_scratch(svm->ghcb),
					svm->ghcb_sa, svm->ghcb_sa_len);
			svm->ghcb_sa_sync = false;
		}

		kfree(svm->ghcb_sa);
		svm->ghcb_sa = NULL;
		svm->ghcb_sa_free = false;
	}

	trace_kvm_vmgexit_exit(svm->vcpu.vcpu_id, svm->ghcb);

	sev_es_sync_to_ghcb(svm);

	kvm_vcpu_unmap(&svm->vcpu, &svm->ghcb_map, true);
	svm->ghcb = NULL;
}

void pre_sev_run(struct vcpu_svm *svm, int cpu)
{
	struct svm_cpu_data *sd = per_cpu(svm_data, cpu);
	int asid = sev_get_asid(svm->vcpu.kvm);

	/* Assign the asid allocated with this SEV guest */
	svm->asid = asid;

	/*
	 * Flush guest TLB:
	 *
	 * 1) when different VMCB for the same ASID is to be run on the same host CPU.
	 * 2) or this VMCB was executed on different host CPU in previous VMRUNs.
	 */
	if (sd->sev_vmcbs[asid] == svm->vmcb &&
	    svm->vcpu.arch.last_vmentry_cpu == cpu)
		return;

	sd->sev_vmcbs[asid] = svm->vmcb;
	svm->vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ASID;
	vmcb_mark_dirty(svm->vmcb, VMCB_ASID);
}

#define GHCB_SCRATCH_AREA_LIMIT		(16ULL * PAGE_SIZE)
static bool setup_vmgexit_scratch(struct vcpu_svm *svm, bool sync, u64 len)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct ghcb *ghcb = svm->ghcb;
	u64 ghcb_scratch_beg, ghcb_scratch_end;
	u64 scratch_gpa_beg, scratch_gpa_end;
	void *scratch_va;

	scratch_gpa_beg = ghcb_get_sw_scratch(ghcb);
	if (!scratch_gpa_beg) {
		pr_err("vmgexit: scratch gpa not provided\n");
		return false;
	}

	scratch_gpa_end = scratch_gpa_beg + len;
	if (scratch_gpa_end < scratch_gpa_beg) {
		pr_err("vmgexit: scratch length (%#llx) not valid for scratch address (%#llx)\n",
		       len, scratch_gpa_beg);
		return false;
	}

	if ((scratch_gpa_beg & PAGE_MASK) == control->ghcb_gpa) {
		/* Scratch area begins within GHCB */
		ghcb_scratch_beg = control->ghcb_gpa +
				   offsetof(struct ghcb, shared_buffer);
		ghcb_scratch_end = control->ghcb_gpa +
				   offsetof(struct ghcb, reserved_1);

		/*
		 * If the scratch area begins within the GHCB, it must be
		 * completely contained in the GHCB shared buffer area.
		 */
		if (scratch_gpa_beg < ghcb_scratch_beg ||
		    scratch_gpa_end > ghcb_scratch_end) {
			pr_err("vmgexit: scratch area is outside of GHCB shared buffer area (%#llx - %#llx)\n",
			       scratch_gpa_beg, scratch_gpa_end);
			return false;
		}

		scratch_va = (void *)svm->ghcb;
		scratch_va += (scratch_gpa_beg - control->ghcb_gpa);
	} else {
		/*
		 * The guest memory must be read into a kernel buffer, so
		 * limit the size
		 */
		if (len > GHCB_SCRATCH_AREA_LIMIT) {
			pr_err("vmgexit: scratch area exceeds KVM limits (%#llx requested, %#llx limit)\n",
			       len, GHCB_SCRATCH_AREA_LIMIT);
			return false;
		}
		scratch_va = kzalloc(len, GFP_KERNEL_ACCOUNT);
		if (!scratch_va)
			return false;

		if (kvm_read_guest(svm->vcpu.kvm, scratch_gpa_beg, scratch_va, len)) {
			/* Unable to copy scratch area from guest */
			pr_err("vmgexit: kvm_read_guest for scratch area failed\n");

			kfree(scratch_va);
			return false;
		}

		/*
		 * The scratch area is outside the GHCB. The operation will
		 * dictate whether the buffer needs to be synced before running
		 * the vCPU next time (i.e. a read was requested so the data
		 * must be written back to the guest memory).
		 */
		svm->ghcb_sa_sync = sync;
		svm->ghcb_sa_free = true;
	}

	svm->ghcb_sa = scratch_va;
	svm->ghcb_sa_len = len;

	return true;
}

static void set_ghcb_msr_bits(struct vcpu_svm *svm, u64 value, u64 mask,
			      unsigned int pos)
{
	svm->vmcb->control.ghcb_gpa &= ~(mask << pos);
	svm->vmcb->control.ghcb_gpa |= (value & mask) << pos;
}

static u64 get_ghcb_msr_bits(struct vcpu_svm *svm, u64 mask, unsigned int pos)
{
	return (svm->vmcb->control.ghcb_gpa >> pos) & mask;
}

static void set_ghcb_msr(struct vcpu_svm *svm, u64 value)
{
	svm->vmcb->control.ghcb_gpa = value;
}

static int snp_rmptable_psmash(struct kvm_vcpu *vcpu, kvm_pfn_t pfn)
{
	pfn = pfn & ~(KVM_PAGES_PER_HPAGE(PG_LEVEL_2M) - 1);

	return psmash(pfn_to_page(pfn));
}

static int snp_make_page_shared(struct kvm_vcpu *vcpu, gpa_t gpa, kvm_pfn_t pfn, int level)
{
	struct rmpupdate val;
	int rc, rmp_level;
	struct rmpentry *e;

	e = snp_lookup_page_in_rmptable(pfn_to_page(pfn), &rmp_level);
	if (!e)
		return -EINVAL;

	if (!rmpentry_assigned(e))
		return 0;

	/* Log if the entry is validated */
	if (rmpentry_validated(e))
		pr_warn_ratelimited("Remove RMP entry for a validated gpa 0x%llx\n", gpa);

	/*
	 * Is the page part of an existing 2M RMP entry ? Split the 2MB into multiple
	 * of 4K-page before making the memory shared.
	 */
	if ((level == PG_LEVEL_4K) && (rmp_level == PG_LEVEL_2M)) {
		rc = snp_rmptable_psmash(vcpu, pfn);
		if (rc)
			return rc;
	}

	memset(&val, 0, sizeof(val));
	val.pagesize = X86_TO_RMP_PG_LEVEL(level);
	return rmpupdate(pfn_to_page(pfn), &val);
}

static inline bool kvm_host_write_track_gpa_range_is_active(struct kvm *kvm,
							    gpa_t start, gpa_t end)
{
	while (start < end) {
		if (kvm_host_write_track_is_active(kvm, gpa_to_gfn(start)))
			return 1;

		start += PAGE_SIZE;
	}

	return false;
}

static int snp_make_page_private(struct kvm_vcpu *vcpu, gpa_t gpa, kvm_pfn_t pfn, int level)
{
	struct kvm_sev_info *sev = &to_kvm_svm(vcpu->kvm)->sev_info;
	struct rmpupdate val;
	struct rmpentry *e;
	int rmp_level;

	e = snp_lookup_page_in_rmptable(pfn_to_page(pfn), &rmp_level);
	if (!e)
		return -EINVAL;

	/*
	 * If the GPA is tracked for the write access then do not change the
	 * page state from shared to private.
	 */
	if (kvm_host_write_track_gpa_range_is_active(vcpu->kvm,
		gpa, gpa + page_level_size(level)))
		return -EBUSY;

	/* Log if the entry is validated */
	if (rmpentry_validated(e))
		pr_warn_ratelimited("Asked to make a pre-validated gpa %llx private\n", gpa);

	memset(&val, 0, sizeof(val));
	val.gpa = gpa;
	val.asid = sev->asid;
	val.pagesize = X86_TO_RMP_PG_LEVEL(level);
	val.assigned = true;

	return rmpupdate(pfn_to_page(pfn), &val);
}

static int __snp_handle_psc(struct kvm_vcpu *vcpu, int op, gpa_t gpa, int level)
{
	struct kvm *kvm = vcpu->kvm;
	int rc = PSC_UNDEF_ERR;
	int tdp_level;
	kvm_pfn_t pfn;
	gpa_t gpa_end;

	gpa_end = gpa + page_level_size(level);

	while (gpa < gpa_end) {
		/*
		 * Get the pfn and level for the gpa from the nested page table.
		 *
		 * If the TDP walk failed, then its safe to say that we don't have a valid
		 * mapping for the gpa in the nested page table. Create a fault to map the
		 * page is nested page table.
		 */
		if (!kvm_mmu_get_tdp_walk(vcpu, gpa, &pfn, &tdp_level)) {
			pfn = kvm_mmu_map_tdp_page(vcpu, gpa, PFERR_USER_MASK, level);
			if (is_error_noslot_pfn(pfn))
				goto out;

			if (!kvm_mmu_get_tdp_walk(vcpu, gpa, &pfn, &tdp_level))
				goto out;
		}

		/* Adjust the level so that we don't go higher than the backing page level */
		level = min_t(size_t, level, tdp_level);

		write_lock(&kvm->mmu_lock);

		switch (op) {
		case SNP_PAGE_STATE_SHARED:
			rc = snp_make_page_shared(vcpu, gpa, pfn, level);
			break;
		case SNP_PAGE_STATE_PRIVATE:
			rc = snp_make_page_private(vcpu, gpa, pfn, level);
			break;
		case SNP_PAGE_STATE_PSMASH:
		case SNP_PAGE_STATE_UNSMASH:
			/* TODO: Add support to handle it */
		default:
			rc = PSC_INVALID_ENTRY;
			break;
		}

		write_unlock(&kvm->mmu_lock);

		if (rc) {
			pr_err_ratelimited("Error op %d gpa %llx pfn %llx level %d rc %d\n",
					   op, gpa, pfn, level, rc);
			goto out;
		}

		gpa = gpa + page_level_size(level);
	}

out:
	return rc;
}

static inline unsigned long map_to_psc_vmgexit_code(int rc)
{
	switch (rc) {
	case PSC_INVALID_HDR:
		return ((1ul << 32) | 1);
	case PSC_INVALID_ENTRY:
		return ((1ul << 32) | 2);
	case RMPUPDATE_FAIL_OVERLAP:
		return ((3ul << 32) | 2);
	default: return (4ul << 32);
	}
}

static unsigned long snp_handle_psc(struct vcpu_svm *svm, struct ghcb *ghcb)
{
	struct kvm_vcpu *vcpu = &svm->vcpu;
	int level, op, rc = PSC_UNDEF_ERR;
	struct snp_psc_desc *info;
	struct psc_entry *entry;
	gpa_t gpa;

	if (!sev_snp_guest(vcpu->kvm))
		goto out;

	if (!setup_vmgexit_scratch(svm, true, sizeof(ghcb->save.sw_scratch))) {
		pr_err("vmgexit: scratch area is not setup.\n");
		rc = PSC_INVALID_HDR;
		goto out;
	}

	info = (struct snp_psc_desc *)svm->ghcb_sa;
	entry = &info->entries[info->hdr.cur_entry];

	if ((info->hdr.cur_entry >= VMGEXIT_PSC_MAX_ENTRY) ||
	    (info->hdr.end_entry >= VMGEXIT_PSC_MAX_ENTRY) ||
	    (info->hdr.cur_entry > info->hdr.end_entry)) {
		rc = PSC_INVALID_ENTRY;
		goto out;
	}

	while (info->hdr.cur_entry <= info->hdr.end_entry) {
		entry = &info->entries[info->hdr.cur_entry];
		gpa = gfn_to_gpa(entry->gfn);
		level = RMP_TO_X86_PG_LEVEL(entry->pagesize);
		op = entry->operation;

		if (!IS_ALIGNED(gpa, page_level_size(level))) {
			rc = PSC_INVALID_ENTRY;
			goto out;
		}

		rc = __snp_handle_psc(vcpu, op, gpa, level);
		if (rc)
			goto out;

		info->hdr.cur_entry++;
	}

out:
	return rc ? map_to_psc_vmgexit_code(rc) : 0;
}

static int snp_build_guest_buf(struct vcpu_svm *svm, struct sev_data_snp_guest_request *data,
			       gpa_t req_gpa, gpa_t resp_gpa)
{
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct kvm *kvm = vcpu->kvm;
	kvm_pfn_t req_pfn, resp_pfn;
	struct kvm_sev_info *sev;

	if (!IS_ALIGNED(req_gpa, PAGE_SIZE) || !IS_ALIGNED(resp_gpa, PAGE_SIZE)) {
		pr_err_ratelimited("svm: guest request (%#llx) or response (%#llx) is not page aligned\n",
			req_gpa, resp_gpa);
		return -EINVAL;
	}

	req_pfn = gfn_to_pfn(kvm, gpa_to_gfn(req_gpa));
	if (is_error_noslot_pfn(req_pfn)) {
		pr_err_ratelimited("svm: guest request invalid gpa=%#llx\n", req_gpa);
		return -EINVAL;
	}

	resp_pfn = gfn_to_pfn(kvm, gpa_to_gfn(resp_gpa));
	if (is_error_noslot_pfn(resp_pfn)) {
		pr_err_ratelimited("svm: guest response invalid gpa=%#llx\n", resp_gpa);
		return -EINVAL;
	}

	sev = &to_kvm_svm(kvm)->sev_info;

	data->gctx_paddr = __psp_pa(sev->snp_context);
	data->req_paddr = __sme_set(req_pfn << PAGE_SHIFT);
	data->res_paddr = __psp_pa(sev->snp_resp_page);

	return 0;
}

static void snp_handle_guest_request(struct vcpu_svm *svm, struct ghcb *ghcb,
				     gpa_t req_gpa, gpa_t resp_gpa)
{
	struct sev_data_snp_guest_request data = {};
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_sev_info *sev;
	int rc, err = 0;

	if (!sev_snp_guest(vcpu->kvm)) {
		rc = -ENODEV;
		goto e_fail;
	}

	sev = &to_kvm_svm(kvm)->sev_info;

	if (!__ratelimit(&sev->snp_guest_msg_rs)) {
		pr_info_ratelimited("svm: too many guest message requests\n");
		rc = -EAGAIN;
		goto e_fail;
	}

	rc = snp_build_guest_buf(svm, &data, req_gpa, resp_gpa);
	if (rc)
		goto e_fail;

	sev = &to_kvm_svm(kvm)->sev_info;

	mutex_lock(&kvm->lock);

	rc = sev_issue_cmd(kvm, SEV_CMD_SNP_GUEST_REQUEST, &data, &err);
	if (rc) {
		mutex_unlock(&kvm->lock);

		/* If we have a firmware error code then use it. */
		if (err)
			rc = err;

		goto e_fail;
	}

	/* Copy the response after the firmware returns success. */
	rc = kvm_write_guest(kvm, resp_gpa, sev->snp_resp_page, PAGE_SIZE);

	mutex_unlock(&kvm->lock);

e_fail:
	ghcb_set_sw_exit_info_2(ghcb, rc);
}

static void snp_handle_ext_guest_request(struct vcpu_svm *svm, struct ghcb *ghcb,
					 gpa_t req_gpa, gpa_t resp_gpa)
{
	struct sev_data_snp_guest_request req = {};
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct kvm *kvm = vcpu->kvm;
	unsigned long data_npages;
	struct kvm_sev_info *sev;
	unsigned long err;
	u64 data_gpa;
	int rc;

	if (!sev_snp_guest(vcpu->kvm)) {
		rc = -ENODEV;
		goto e_fail;
	}

	sev = &to_kvm_svm(kvm)->sev_info;

	if (!__ratelimit(&sev->snp_guest_msg_rs)) {
		pr_info_ratelimited("svm: too many guest message requests\n");
		rc = -EAGAIN;
		goto e_fail;
	}

	if (!sev->snp_certs_data) {
		pr_err("svm: certs data memory is not allocated\n");
		rc = -EFAULT;
		goto e_fail;
	}

	data_gpa = ghcb_get_rax(ghcb);
	data_npages = ghcb_get_rbx(ghcb);

	if (!IS_ALIGNED(data_gpa, PAGE_SIZE)) {
		pr_err_ratelimited("svm: certs data GPA is not page aligned (%#llx)\n", data_gpa);
		rc = -EINVAL;
		goto e_fail;
	}

	/* Verify that requested blob will fit in our intermediate buffer */
	if ((data_npages << PAGE_SHIFT) > SEV_FW_BLOB_MAX_SIZE) {
		rc = -EINVAL;
		goto e_fail;
	}

	rc = snp_build_guest_buf(svm, &req, req_gpa, resp_gpa);
	if (rc)
		goto e_fail;

	mutex_lock(&kvm->lock);
	rc = snp_guest_ext_guest_request(&req, (unsigned long)sev->snp_certs_data,
					 &data_npages, &err);
	if (rc) {
		mutex_unlock(&kvm->lock);

		/*
		 * If buffer length is small then return the expected
		 * length in rbx.
		 */
		if (err == SNP_GUEST_REQ_INVALID_LEN) {
			vcpu->arch.regs[VCPU_REGS_RBX] = data_npages;
			ghcb_set_sw_exit_info_2(ghcb, err);
			return;
		}

		/* If we have a firmware error code then use it. */
		if (err)
			rc = (int)err;

		goto e_fail;
	}

	/* Copy the response after the firmware returns success. */
	rc = kvm_write_guest(kvm, resp_gpa, sev->snp_resp_page, PAGE_SIZE);

	mutex_unlock(&kvm->lock);

	if (rc)
		goto e_fail;

	/* Copy the certificate blob in the guest memory */
	if (data_npages &&
	    kvm_write_guest(kvm, data_gpa, sev->snp_certs_data, data_npages << PAGE_SHIFT))
		rc = -EFAULT;

e_fail:
	ghcb_set_sw_exit_info_2(ghcb, rc);
}

static int sev_handle_vmgexit_msr_protocol(struct vcpu_svm *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct kvm_vcpu *vcpu = &svm->vcpu;
	u64 ghcb_info;
	int ret = 1;

	ghcb_info = control->ghcb_gpa & GHCB_MSR_INFO_MASK;

	trace_kvm_vmgexit_msr_protocol_enter(svm->vcpu.vcpu_id,
					     control->ghcb_gpa);

	switch (ghcb_info) {
	case GHCB_MSR_SEV_INFO_REQ:
		set_ghcb_msr(svm, GHCB_MSR_SEV_INFO(GHCB_VERSION_MAX,
						    GHCB_VERSION_MIN,
						    sev_enc_bit));
		break;
	case GHCB_MSR_CPUID_REQ: {
		u64 cpuid_fn, cpuid_reg, cpuid_value;

		cpuid_fn = get_ghcb_msr_bits(svm,
					     GHCB_MSR_CPUID_FUNC_MASK,
					     GHCB_MSR_CPUID_FUNC_POS);

		/* Initialize the registers needed by the CPUID intercept */
		vcpu->arch.regs[VCPU_REGS_RAX] = cpuid_fn;
		vcpu->arch.regs[VCPU_REGS_RCX] = 0;

		ret = svm_invoke_exit_handler(vcpu, SVM_EXIT_CPUID);
		if (!ret) {
			ret = -EINVAL;
			break;
		}

		cpuid_reg = get_ghcb_msr_bits(svm,
					      GHCB_MSR_CPUID_REG_MASK,
					      GHCB_MSR_CPUID_REG_POS);
		if (cpuid_reg == 0)
			cpuid_value = vcpu->arch.regs[VCPU_REGS_RAX];
		else if (cpuid_reg == 1)
			cpuid_value = vcpu->arch.regs[VCPU_REGS_RBX];
		else if (cpuid_reg == 2)
			cpuid_value = vcpu->arch.regs[VCPU_REGS_RCX];
		else
			cpuid_value = vcpu->arch.regs[VCPU_REGS_RDX];

		set_ghcb_msr_bits(svm, cpuid_value,
				  GHCB_MSR_CPUID_VALUE_MASK,
				  GHCB_MSR_CPUID_VALUE_POS);

		set_ghcb_msr_bits(svm, GHCB_MSR_CPUID_RESP,
				  GHCB_MSR_INFO_MASK,
				  GHCB_MSR_INFO_POS);
		break;
	}
	case GHCB_MSR_AP_RESET_HOLD_REQ:
		svm->ap_reset_hold_type = AP_RESET_HOLD_MSR_PROTO;
		ret = kvm_emulate_ap_reset_hold(&svm->vcpu);

		/*
		 * Preset the result to a non-SIPI return and then only set
		 * the result to non-zero when delivering a SIPI.
		 */
		set_ghcb_msr_bits(svm, 0,
				  GHCB_MSR_AP_RESET_HOLD_RESULT_MASK,
				  GHCB_MSR_AP_RESET_HOLD_RESULT_POS);

		set_ghcb_msr_bits(svm, GHCB_MSR_AP_RESET_HOLD_RESP,
				  GHCB_MSR_INFO_MASK,
				  GHCB_MSR_INFO_POS);
		break;
	case GHCB_MSR_HV_FT_REQ: {
		set_ghcb_msr_bits(svm, GHCB_HV_FT_SUPPORTED,
				GHCB_MSR_HV_FT_MASK, GHCB_MSR_HV_FT_POS);
		set_ghcb_msr_bits(svm, GHCB_MSR_HV_FT_RESP,
				GHCB_MSR_INFO_MASK, GHCB_MSR_INFO_POS);
		break;
	}
	case GHCB_MSR_GPA_REG_REQ: {
		kvm_pfn_t pfn;
		u64 gfn;

		gfn = get_ghcb_msr_bits(svm, GHCB_MSR_GPA_REG_GFN_MASK,
					GHCB_MSR_GPA_REG_VALUE_POS);

		pfn = kvm_vcpu_gfn_to_pfn(vcpu, gfn);
		if (is_error_noslot_pfn(pfn))
			gfn = GHCB_MSR_GPA_REG_ERROR;
		else
			svm->ghcb_registered_gpa = gfn_to_gpa(gfn);

		set_ghcb_msr_bits(svm, gfn, GHCB_MSR_GPA_REG_GFN_MASK,
				  GHCB_MSR_GPA_REG_VALUE_POS);
		set_ghcb_msr_bits(svm, GHCB_MSR_GPA_REG_RESP, GHCB_MSR_INFO_MASK,
				  GHCB_MSR_INFO_POS);
		break;
	}
	case GHCB_MSR_PSC_REQ: {
		gfn_t gfn;
		int ret;
		u8 op;

		gfn = get_ghcb_msr_bits(svm, GHCB_MSR_PSC_GFN_MASK, GHCB_MSR_PSC_GFN_POS);
		op = get_ghcb_msr_bits(svm, GHCB_MSR_PSC_OP_MASK, GHCB_MSR_PSC_OP_POS);

		ret = __snp_handle_psc(vcpu, op, gfn_to_gpa(gfn), PG_LEVEL_4K);

		/* If failed to change the state then spec requires to return all F's */
		if (ret)
			ret = -1;

		set_ghcb_msr_bits(svm, ret, GHCB_MSR_PSC_ERROR_MASK, GHCB_MSR_PSC_ERROR_POS);
		set_ghcb_msr_bits(svm, 0, GHCB_MSR_PSC_RSVD_MASK, GHCB_MSR_PSC_RSVD_POS);
		set_ghcb_msr_bits(svm, GHCB_MSR_PSC_RESP, GHCB_MSR_INFO_MASK, GHCB_MSR_INFO_POS);
		break;
	}
	case GHCB_MSR_TERM_REQ: {
		u64 reason_set, reason_code;

		reason_set = get_ghcb_msr_bits(svm,
					       GHCB_MSR_TERM_REASON_SET_MASK,
					       GHCB_MSR_TERM_REASON_SET_POS);
		reason_code = get_ghcb_msr_bits(svm,
						GHCB_MSR_TERM_REASON_MASK,
						GHCB_MSR_TERM_REASON_POS);
		pr_info("SEV-ES guest requested termination: %#llx:%#llx\n",
			reason_set, reason_code);
		fallthrough;
	}
	default:
		ret = -EINVAL;
	}

	trace_kvm_vmgexit_msr_protocol_exit(svm->vcpu.vcpu_id,
					    control->ghcb_gpa, ret);

	return ret;
}

void sev_snp_update_protected_guest_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	kvm_pfn_t pfn;

	mutex_lock(&svm->snp_vmsa_mutex);

	vcpu->arch.mp_state = KVM_MP_STATE_UNINITIALIZED;

	/* Clear use of the VMSA in the sev_es_init_vmcb() path */
	svm->vmsa_pa = 0;

	/* Clear use of the VMSA from the VMCB */
	svm->vmcb->control.vmsa_pa = 0;

	/* Un-pin previous VMSA */
	if (svm->snp_vmsa_pfn) {
		kvm_release_pfn_dirty(svm->snp_vmsa_pfn);
		svm->snp_vmsa_pfn = 0;
	}

	if (svm->snp_vmsa_gpa) {
		/* Validate that the GPA is page aligned */
		if (!PAGE_ALIGNED(svm->snp_vmsa_gpa))
			goto e_unlock;

		/*
		 * The VMSA is referenced by thy hypervisor physical address,
		 * so retrieve the PFN and pin it.
		 */
		pfn = gfn_to_pfn(vcpu->kvm, gpa_to_gfn(svm->snp_vmsa_gpa));
		if (is_error_pfn(pfn))
			goto e_unlock;

		svm->snp_vmsa_pfn = pfn;

		/* Use the new VMSA in the sev_es_init_vmcb() path */
		svm->vmsa_pa = pfn_to_hpa(pfn);
		svm->vmcb->control.vmsa_pa = svm->vmsa_pa;

		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	} else {
		vcpu->arch.pv.pv_unhalted = false;
		vcpu->arch.mp_state = KVM_MP_STATE_UNINITIALIZED;
	}

e_unlock:
	mutex_unlock(&svm->snp_vmsa_mutex);
}

static void sev_snp_ap_creation(struct vcpu_svm *svm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(svm->vcpu.kvm)->sev_info;
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct kvm_vcpu *target_vcpu;
	struct vcpu_svm *target_svm;
	unsigned int request;
	unsigned int apic_id;
	bool kick;

	request = lower_32_bits(svm->vmcb->control.exit_info_1);
	apic_id = upper_32_bits(svm->vmcb->control.exit_info_1);

	/* Validate the APIC ID */
	target_vcpu = kvm_get_vcpu_by_id(vcpu->kvm, apic_id);
	if (!target_vcpu)
		return;

	target_svm = to_svm(target_vcpu);

	kick = true;

	mutex_lock(&target_svm->snp_vmsa_mutex);

	target_svm->snp_vmsa_gpa = 0;
	target_svm->snp_vmsa_update_on_init = false;

	/* Interrupt injection mode shouldn't change for AP creation */
	if (request < SVM_VMGEXIT_AP_DESTROY) {
		u64 sev_features;

		sev_features = vcpu->arch.regs[VCPU_REGS_RAX];
		sev_features ^= sev->sev_features;
		if (sev_features & SVM_SEV_FEATURES_INT_INJ_MODES) {
			vcpu_unimpl(vcpu, "vmgexit: invalid AP injection mode [%#lx] from guest\n",
				    vcpu->arch.regs[VCPU_REGS_RAX]);
			goto out;
		}
	}

	switch (request) {
	case SVM_VMGEXIT_AP_CREATE_ON_INIT:
		kick = false;
		target_svm->snp_vmsa_update_on_init = true;
		fallthrough;
	case SVM_VMGEXIT_AP_CREATE:
		target_svm->snp_vmsa_gpa = svm->vmcb->control.exit_info_2;
		break;
	case SVM_VMGEXIT_AP_DESTROY:
		break;
	default:
		vcpu_unimpl(vcpu, "vmgexit: invalid AP creation request [%#x] from guest\n",
			    request);
		break;
	}

out:
	mutex_unlock(&target_svm->snp_vmsa_mutex);

	if (kick) {
		kvm_make_request(KVM_REQ_UPDATE_PROTECTED_GUEST_STATE, target_vcpu);
		kvm_vcpu_kick(target_vcpu);
	}
}

int sev_handle_vmgexit(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb_control_area *control = &svm->vmcb->control;
	u64 ghcb_gpa, exit_code;
	struct ghcb *ghcb;
	int ret;

	/* Validate the GHCB */
	ghcb_gpa = control->ghcb_gpa;
	if (ghcb_gpa & GHCB_MSR_INFO_MASK)
		return sev_handle_vmgexit_msr_protocol(svm);

	if (!ghcb_gpa) {
		vcpu_unimpl(vcpu, "vmgexit: GHCB gpa is not set\n");
		return -EINVAL;
	}

	if (kvm_vcpu_map(vcpu, ghcb_gpa >> PAGE_SHIFT, &svm->ghcb_map)) {
		/* Unable to map GHCB from guest */
		vcpu_unimpl(vcpu, "vmgexit: error mapping GHCB [%#llx] from guest\n",
			    ghcb_gpa);
		return -EINVAL;
	}

	/* SEV-SNP guest requires that the GHCB GPA must be registered */
	if (sev_snp_guest(svm->vcpu.kvm) && !ghcb_gpa_is_registered(svm, ghcb_gpa)) {
		vcpu_unimpl(&svm->vcpu, "vmgexit: GHCB GPA [%#llx] is not registered.\n", ghcb_gpa);
		return -EINVAL;
	}

	svm->ghcb = svm->ghcb_map.hva;
	ghcb = svm->ghcb_map.hva;

	trace_kvm_vmgexit_enter(vcpu->vcpu_id, ghcb);

	exit_code = ghcb_get_sw_exit_code(ghcb);

	ret = sev_es_validate_vmgexit(svm);
	if (ret)
		return ret;

	sev_es_sync_from_ghcb(svm);
	ghcb_set_sw_exit_info_1(ghcb, 0);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	ret = -EINVAL;
	switch (exit_code) {
	case SVM_VMGEXIT_MMIO_READ:
		if (!setup_vmgexit_scratch(svm, true, control->exit_info_2))
			break;

		ret = kvm_sev_es_mmio_read(vcpu,
					   control->exit_info_1,
					   control->exit_info_2,
					   svm->ghcb_sa);
		break;
	case SVM_VMGEXIT_MMIO_WRITE:
		if (!setup_vmgexit_scratch(svm, false, control->exit_info_2))
			break;

		ret = kvm_sev_es_mmio_write(vcpu,
					    control->exit_info_1,
					    control->exit_info_2,
					    svm->ghcb_sa);
		break;
	case SVM_VMGEXIT_NMI_COMPLETE:
		ret = svm_invoke_exit_handler(vcpu, SVM_EXIT_IRET);
		break;
	case SVM_VMGEXIT_AP_HLT_LOOP:
		svm->ap_reset_hold_type = AP_RESET_HOLD_NAE_EVENT;
		ret = kvm_emulate_ap_reset_hold(vcpu);
		break;
	case SVM_VMGEXIT_AP_JUMP_TABLE: {
		struct kvm_sev_info *sev = &to_kvm_svm(vcpu->kvm)->sev_info;

		switch (control->exit_info_1) {
		case 0:
			/* Set AP jump table address */
			sev->ap_jump_table = control->exit_info_2;
			break;
		case 1:
			/* Get AP jump table address */
			ghcb_set_sw_exit_info_2(ghcb, sev->ap_jump_table);
			break;
		default:
			pr_err("svm: vmgexit: unsupported AP jump table request - exit_info_1=%#llx\n",
			       control->exit_info_1);
			ghcb_set_sw_exit_info_1(ghcb, 1);
			ghcb_set_sw_exit_info_2(ghcb,
						X86_TRAP_UD |
						SVM_EVTINJ_TYPE_EXEPT |
						SVM_EVTINJ_VALID);
		}

		ret = 1;
		break;
	}
	case SVM_VMGEXIT_HV_FT: {
		ghcb_set_sw_exit_info_2(ghcb, GHCB_HV_FT_SUPPORTED);

		ret = 1;
		break;
	}
	case SVM_VMGEXIT_PSC: {
		unsigned long rc;

		ret = 1;

		rc = snp_handle_psc(svm, ghcb);
		ghcb_set_sw_exit_info_2(ghcb, rc);
		break;
	}
	case SVM_VMGEXIT_GUEST_REQUEST: {
		snp_handle_guest_request(svm, ghcb, control->exit_info_1, control->exit_info_2);

		ret = 1;
		break;
	}
	case SVM_VMGEXIT_EXT_GUEST_REQUEST: {
		snp_handle_ext_guest_request(svm,
					     ghcb,
					     control->exit_info_1,
					     control->exit_info_2);

		ret = 1;
		break;
	}
	case SVM_VMGEXIT_AP_CREATION:
		sev_snp_ap_creation(svm);

		ret = 1;
		break;
	case SVM_VMGEXIT_UNSUPPORTED_EVENT:
		vcpu_unimpl(vcpu,
			    "vmgexit: unsupported event - exit_info_1=%#llx, exit_info_2=%#llx\n",
			    control->exit_info_1, control->exit_info_2);
		break;
	default:
		ret = svm_invoke_exit_handler(vcpu, exit_code);
	}

	return ret;
}

int sev_es_string_io(struct vcpu_svm *svm, int size, unsigned int port, int in)
{
	if (!setup_vmgexit_scratch(svm, in, svm->vmcb->control.exit_info_2))
		return -EINVAL;

	return kvm_sev_es_string_io(&svm->vcpu, size, port,
				    svm->ghcb_sa, svm->ghcb_sa_len, in);
}

void sev_es_init_vmcb(struct vcpu_svm *svm)
{
	struct kvm_vcpu *vcpu = &svm->vcpu;

	svm->vmcb->control.nested_ctl |= SVM_NESTED_CTL_SEV_ES_ENABLE;
	svm->vmcb->control.virt_ext |= LBR_CTL_ENABLE_MASK;

	/*
	 * An SEV-ES guest requires a VMSA area that is a separate from the
	 * VMCB page.
	 */
	svm->vmcb->control.vmsa_pa = svm->vmsa_pa;

	/* Can't intercept CR register access, HV can't modify CR registers */
	svm_clr_intercept(svm, INTERCEPT_CR0_READ);
	svm_clr_intercept(svm, INTERCEPT_CR4_READ);
	svm_clr_intercept(svm, INTERCEPT_CR8_READ);
	svm_clr_intercept(svm, INTERCEPT_CR0_WRITE);
	svm_clr_intercept(svm, INTERCEPT_CR4_WRITE);
	svm_clr_intercept(svm, INTERCEPT_CR8_WRITE);

	svm_clr_intercept(svm, INTERCEPT_SELECTIVE_CR0);

	/* Track EFER/CR register changes */
	svm_set_intercept(svm, TRAP_EFER_WRITE);
	svm_set_intercept(svm, TRAP_CR0_WRITE);
	svm_set_intercept(svm, TRAP_CR4_WRITE);
	svm_set_intercept(svm, TRAP_CR8_WRITE);

	/* No support for enable_vmware_backdoor */
	clr_exception_intercept(svm, GP_VECTOR);

	/* Can't intercept XSETBV, HV can't modify XCR0 directly */
	svm_clr_intercept(svm, INTERCEPT_XSETBV);

	/* Clear intercepts on selected MSRs */
	set_msr_interception(vcpu, svm->msrpm, MSR_EFER, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_CR_PAT, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTBRANCHFROMIP, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTBRANCHTOIP, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTINTFROMIP, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTINTTOIP, 1, 1);
}

void sev_es_create_vcpu(struct vcpu_svm *svm)
{
	/*
	 * Set the GHCB MSR value as per the GHCB specification when creating
	 * a vCPU for an SEV-ES guest.
	 */
	set_ghcb_msr(svm, GHCB_MSR_SEV_INFO(GHCB_VERSION_MAX,
					    GHCB_VERSION_MIN,
					    sev_enc_bit));

	mutex_init(&svm->snp_vmsa_mutex);
}

void sev_es_prepare_guest_switch(struct vcpu_svm *svm, unsigned int cpu)
{
	struct svm_cpu_data *sd = per_cpu(svm_data, cpu);
	struct sev_es_save_area *hostsa;

	/*
	 * As an SEV-ES guest, hardware will restore the host state on VMEXIT,
	 * of which one step is to perform a VMLOAD. Since hardware does not
	 * perform a VMSAVE on VMRUN, the host savearea must be updated.
	 */
	vmsave(__sme_page_pa(sd->save_area));

	/* XCR0 is restored on VMEXIT, save the current host value */
	hostsa = (struct sev_es_save_area *)(page_address(sd->save_area) + 0x400);
	hostsa->xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);

	/* PKRU is restored on VMEXIT, save the current host value */
	hostsa->pkru = read_pkru();

	/* MSR_IA32_XSS is restored on VMEXIT, save the currnet host value */
	hostsa->xss = host_xss;
}

void sev_vcpu_deliver_sipi_vector(struct kvm_vcpu *vcpu, u8 vector)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	/* First SIPI: Use the values as initially set by the VMM */
	if (!svm->received_first_sipi) {
		svm->received_first_sipi = true;
		return;
	}

	/* Subsequent SIPI */
	switch (svm->ap_reset_hold_type) {
	case AP_RESET_HOLD_NAE_EVENT:
		/*
		 * Return from an AP Reset Hold VMGEXIT, where the guest will
		 * set the CS and RIP. Set SW_EXIT_INFO_2 to a non-zero value.
		 */
		ghcb_set_sw_exit_info_2(svm->ghcb, 1);
		break;
	case AP_RESET_HOLD_MSR_PROTO:
		/*
		 * Return from an AP Reset Hold VMGEXIT, where the guest will
		 * set the CS and RIP. Set GHCB data field to a non-zero value.
		 */
		set_ghcb_msr_bits(svm, 1,
				  GHCB_MSR_AP_RESET_HOLD_RESULT_MASK,
				  GHCB_MSR_AP_RESET_HOLD_RESULT_POS);

		set_ghcb_msr_bits(svm, GHCB_MSR_AP_RESET_HOLD_RESP,
				  GHCB_MSR_INFO_MASK,
				  GHCB_MSR_INFO_POS);
		break;
	default:
		break;
	}
}

struct page *snp_safe_alloc_page(struct kvm_vcpu *vcpu)
{
	unsigned long pfn;
	struct page *p;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);

	p = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, 1);
	if (!p)
		return NULL;

	/* split the page order */
	split_page(p, 1);

	/* Find a non-2M aligned page */
	pfn = page_to_pfn(p);
	if (IS_ALIGNED(__pfn_to_phys(pfn), PMD_SIZE)) {
		pfn++;
		__free_page(p);
	} else {
		__free_page(pfn_to_page(pfn + 1));
	}

	return pfn_to_page(pfn);
}

int sev_get_tdp_max_page_level(struct kvm_vcpu *vcpu, gpa_t gpa, int max_level)
{
	struct rmpentry *e;
	kvm_pfn_t pfn;
	int level;

	if (!sev_snp_guest(vcpu->kvm))
		return max_level;

	pfn = gfn_to_pfn(vcpu->kvm, gpa_to_gfn(gpa));
	if (is_error_noslot_pfn(pfn))
		return max_level;

	e = snp_lookup_page_in_rmptable(pfn_to_page(pfn), &level);
	if (unlikely(!e))
		return max_level;

	return min_t(uint32_t, level, max_level);
}

void sev_snp_write_page_begin(struct kvm *kvm, struct kvm_memory_slot *slot, gfn_t gfn)
{
	struct rmpentry *e;
	int level, rc;
	kvm_pfn_t pfn;

	if (!sev_snp_guest(kvm))
		return;

	pfn = gfn_to_pfn(kvm, gfn);
	if (is_error_noslot_pfn(pfn))
		return;

	e = snp_lookup_page_in_rmptable(pfn_to_page(pfn), &level);
	if (unlikely(!e))
		return;

	/*
	 * A hypervisor should never write to the guest private page. A write to the
	 * guest private will cause an RMP violation. If the guest page is private,
	 * then make it shared.
	 */
	if (rmpentry_assigned(e)) {
		pr_err("SEV-SNP: write to guest private gfn %llx\n", gfn);
		rc = snp_make_page_shared(kvm_get_vcpu(kvm, 0),
				gfn << PAGE_SHIFT, pfn, PG_LEVEL_4K);
		BUG_ON(rc != 0);
	}
}

int snp_handle_rmp_page_fault(struct kvm_vcpu *vcpu, gpa_t gpa, kvm_pfn_t pfn,
			      int level, u64 error_code)
{
	struct rmpentry *e;
	int rlevel, rc = 0;
	bool private;
	gfn_t gfn;

	e = snp_lookup_page_in_rmptable(pfn_to_page(pfn), &rlevel);
	if (!e)
		return 1;

	private = !!(error_code & PFERR_GUEST_ENC_MASK);

	/*
	 * See APM section 15.36.11 on how to handle the RMP fault for the large pages.
	 *
	 *  npt	     rmp    access      action
	 *  --------------------------------------------------
	 *  4k       2M     C=1       psmash
	 *  x        x      C=1       if page is not private then add a new RMP entry
	 *  x        x      C=0       if page is private then make it shared
	 *  2M       4k     C=x       zap
	 */
	if ((error_code & PFERR_GUEST_SIZEM_MASK) ||
	    ((level == PG_LEVEL_4K) && (rlevel == PG_LEVEL_2M) && private)) {
		rc = snp_rmptable_psmash(vcpu, pfn);
		goto zap_gfn;
	}

	/*
	 * If it's a private access, and the page is not assigned in the RMP table, create a
	 * new private RMP entry.
	 */
	if (!rmpentry_assigned(e) && private) {
		rc = snp_make_page_private(vcpu, gpa, pfn, PG_LEVEL_4K);
		goto zap_gfn;
	}

	/*
	 * If it's a shared access, then make the page shared in the RMP table.
	 */
	if (rmpentry_assigned(e) && !private)
		rc = snp_make_page_shared(vcpu, gpa, pfn, PG_LEVEL_4K);

zap_gfn:
	/*
	 * Now that we have updated the RMP pagesize, zap the existing rmaps for
	 * large entry ranges so that nested page table gets rebuilt with the updated RMP
	 * pagesize.
	 */
	gfn = gpa_to_gfn(gpa) & ~(KVM_PAGES_PER_HPAGE(PG_LEVEL_2M) - 1);
	kvm_zap_gfn_range(vcpu->kvm, gfn, gfn + 512);

	return 0;
}
