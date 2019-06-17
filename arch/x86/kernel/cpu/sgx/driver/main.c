// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <linux/acpi.h>
#include <linux/cdev.h>
#include <linux/mman.h>
#include <linux/platform_device.h>
#include <linux/security.h>
#include <linux/suspend.h>
#include <asm/traps.h>
#include "driver.h"

MODULE_DESCRIPTION("Intel SGX Enclave Driver");
MODULE_AUTHOR("Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>");
MODULE_LICENSE("Dual BSD/GPL");

struct workqueue_struct *sgx_encl_wq;
u64 sgx_encl_size_max_32;
u64 sgx_encl_size_max_64;
u32 sgx_misc_reserved_mask;
u64 sgx_attributes_reserved_mask;
u64 sgx_xfrm_reserved_mask = ~0x3;
u32 sgx_xsave_size_tbl[64];

static int sgx_open(struct inode *inode, struct file *file)
{
	struct sgx_encl *encl;
	int ret;

	encl = kzalloc(sizeof(*encl), GFP_KERNEL);
	if (!encl)
		return -ENOMEM;

	kref_init(&encl->refcount);
	INIT_LIST_HEAD(&encl->add_page_reqs);
	INIT_LIST_HEAD(&encl->va_pages);
	INIT_RADIX_TREE(&encl->page_tree, GFP_KERNEL);
	mutex_init(&encl->lock);
	INIT_LIST_HEAD(&encl->mm_list);
	spin_lock_init(&encl->mm_lock);

	ret = init_srcu_struct(&encl->srcu);
	if (ret) {
		kfree(encl);
		return ret;
	}

	file->private_data = encl;

	return 0;
}

static int sgx_release(struct inode *inode, struct file *file)
{
	struct sgx_encl *encl = file->private_data;
	struct sgx_encl_mm *encl_mm;

	/*
	 * Objects can't be *moved* off an RCU protected list (deletion is ok),
	 * nor can the object be freed until after synchronize_srcu().
	 */
restart:
	spin_lock(&encl->mm_lock);
	if (list_empty(&encl->mm_list)) {
		encl_mm = NULL;
	} else {
		encl_mm = list_first_entry(&encl->mm_list, struct sgx_encl_mm,
					   list);
		list_del_rcu(&encl_mm->list);
	}
	spin_unlock(&encl->mm_lock);

	if (encl_mm) {
		synchronize_srcu(&encl->srcu);

		mmu_notifier_unregister(&encl_mm->mmu_notifier, encl_mm->mm);

		sgx_encl_mm_release(encl_mm);

		goto restart;
	}

	kref_put(&encl->refcount, sgx_encl_release);

	return 0;
}

#ifdef CONFIG_COMPAT
static long sgx_compat_ioctl(struct file *filep, unsigned int cmd,
			      unsigned long arg)
{
	return sgx_ioctl(filep, cmd, arg);
}
#endif

/*
 * Returns the AND of VM_{READ,WRITE,EXEC} permissions across all pages
 * covered by the specific VMA.  A non-existent (or yet to be added) enclave
 * page is considered to have no RWX permissions, i.e. is inaccessible.
 */
static unsigned long sgx_allowed_rwx(struct sgx_encl *encl,
				     struct vm_area_struct *vma,
				     bool *eaug)
{
	unsigned long allowed_rwx = VM_READ | VM_WRITE | VM_EXEC;
	unsigned long idx, idx_start, idx_end;
	struct sgx_encl_page *page;

	idx_start = PFN_DOWN(vma->vm_start);
	idx_end = PFN_DOWN(vma->vm_end - 1);

	for (idx = idx_start; idx <= idx_end; ++idx) {
		/*
		 * No need to take encl->lock, vm_prot_bits is set prior to
		 * insertion and never changes, and racing with adding pages is
		 * a userspace bug.
		 */
		rcu_read_lock();
		page = radix_tree_lookup(&encl->page_tree, idx);
		rcu_read_unlock();

		/* Do not allow R|W|X to a non-existent page. */
		if (!page)
			allowed_rwx = 0;
		else
			allowed_rwx &= page->vm_prot_bits;
		if (page->vm_prot_bits & SGX_VM_EAUG)
			*eaug = true;
		if (!allowed_rwx)
			break;
	}

	return allowed_rwx;
}

static int sgx_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct sgx_encl *encl = file->private_data;
	unsigned long allowed_rwx, prot;
	bool eaug = false;
	int ret;

	allowed_rwx = sgx_allowed_rwx(encl, vma, &eaug);
	if (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC) & ~allowed_rwx)
		return -EACCES;

	prot = _calc_vm_trans(vma->vm_flags, VM_READ, PROT_READ) |
	       _calc_vm_trans(vma->vm_flags, VM_WRITE, PROT_WRITE) |
	       _calc_vm_trans(vma->vm_flags, VM_EXEC, PROT_EXEC);
	ret = security_enclave_map(prot, eaug);
	if (ret)
		return ret;

	ret = sgx_encl_mm_add(encl, vma->vm_mm);
	if (ret)
		return ret;

	if (!(allowed_rwx & VM_READ))
		vma->vm_flags &= ~VM_MAYREAD;
	if (!(allowed_rwx & VM_WRITE))
		vma->vm_flags &= ~VM_MAYWRITE;
	if (!(allowed_rwx & VM_EXEC))
		vma->vm_flags &= ~VM_MAYEXEC;

	vma->vm_ops = &sgx_vm_ops;
	vma->vm_flags |= VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_IO;
	vma->vm_private_data = encl;

	return 0;
}

static unsigned long sgx_get_unmapped_area(struct file *file,
					   unsigned long addr,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags)
{
	if (flags & MAP_PRIVATE)
		return -EINVAL;

	if (flags & MAP_FIXED)
		return addr;

	if (len < 2 * PAGE_SIZE || len & (len - 1))
		return -EINVAL;

	addr = current->mm->get_unmapped_area(file, addr, 2 * len, pgoff,
					      flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	addr = (addr + (len - 1)) & ~(len - 1);

	return addr;
}

static const struct file_operations sgx_encl_fops = {
	.owner			= THIS_MODULE,
	.open			= sgx_open,
	.release		= sgx_release,
	.unlocked_ioctl		= sgx_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= sgx_compat_ioctl,
#endif
	.mmap			= sgx_mmap,
	.get_unmapped_area	= sgx_get_unmapped_area,
};

const struct file_operations sgx_provision_fops = {
	.owner			= THIS_MODULE,
};

static struct bus_type sgx_bus_type = {
	.name	= "sgx",
};

static struct device sgx_encl_dev;
static struct cdev sgx_encl_cdev;
static struct device sgx_provision_dev;
static struct cdev sgx_provision_cdev;
static dev_t sgx_devt;

static void sgx_dev_release(struct device *dev)
{
}

static int sgx_dev_init(const char *name, struct device *dev,
			struct cdev *cdev,
			const struct file_operations *fops,
			int minor)
{
	int ret;

	device_initialize(dev);

	dev->bus = &sgx_bus_type;
	dev->devt = MKDEV(MAJOR(sgx_devt), minor);
	dev->release = sgx_dev_release;

	ret = dev_set_name(dev, name);
	if (ret) {
		put_device(dev);
		return ret;
	}

	cdev_init(cdev, fops);
	cdev->owner = THIS_MODULE;
	return 0;
}

int sgx_drv_init(void)
{
	unsigned int eax, ebx, ecx, edx;
	u64 attr_mask, xfrm_mask;
	int ret;
	int i;

	if (!boot_cpu_has(X86_FEATURE_SGX_LC)) {
		pr_info("sgx: The public key MSRs are not writable\n");
		return 0;
	}

	ret = bus_register(&sgx_bus_type);
	if (ret)
		return ret;

	ret = alloc_chrdev_region(&sgx_devt, 0, SGX_DRV_NR_DEVICES, "sgx");
	if (ret < 0)
		goto err_bus;

	cpuid_count(SGX_CPUID, 0, &eax, &ebx, &ecx, &edx);
	sgx_misc_reserved_mask = ~ebx | SGX_MISC_RESERVED_MASK;
	sgx_encl_size_max_64 = 1ULL << ((edx >> 8) & 0xFF);
	sgx_encl_size_max_32 = 1ULL << (edx & 0xFF);

	cpuid_count(SGX_CPUID, 1, &eax, &ebx, &ecx, &edx);

	attr_mask = (((u64)ebx) << 32) + (u64)eax;
	sgx_attributes_reserved_mask = ~attr_mask | SGX_ATTR_RESERVED_MASK;

	if (boot_cpu_has(X86_FEATURE_OSXSAVE)) {
		xfrm_mask = (((u64)edx) << 32) + (u64)ecx;

		for (i = 2; i < 64; i++) {
			cpuid_count(0x0D, i, &eax, &ebx, &ecx, &edx);
			if ((1 << i) & xfrm_mask)
				sgx_xsave_size_tbl[i] = eax + ebx;
		}

		sgx_xfrm_reserved_mask = ~xfrm_mask;
	}

	ret = sgx_dev_init("sgx/enclave", &sgx_encl_dev, &sgx_encl_cdev,
			   &sgx_encl_fops, 0);
	if (ret)
		goto err_chrdev_region;

	ret = sgx_dev_init("sgx/provision", &sgx_provision_dev,
			   &sgx_provision_cdev, &sgx_provision_fops, 1);
	if (ret)
		goto err_encl_dev;

	sgx_encl_wq = alloc_workqueue("sgx-encl-wq",
				      WQ_UNBOUND | WQ_FREEZABLE, 1);
	if (!sgx_encl_wq) {
		ret = -ENOMEM;
		goto err_provision_dev;
	}

	ret = cdev_device_add(&sgx_encl_cdev, &sgx_encl_dev);
	if (ret)
		goto err_encl_wq;

	ret = cdev_device_add(&sgx_provision_cdev, &sgx_provision_dev);
	if (ret)
		goto err_encl_cdev;

	return 0;

err_encl_cdev:
	cdev_device_del(&sgx_encl_cdev, &sgx_encl_dev);

err_encl_wq:
	destroy_workqueue(sgx_encl_wq);

err_provision_dev:
	put_device(&sgx_provision_dev);

err_encl_dev:
	put_device(&sgx_encl_dev);

err_chrdev_region:
	unregister_chrdev_region(sgx_devt, SGX_DRV_NR_DEVICES);

err_bus:
	bus_unregister(&sgx_bus_type);

	return ret;
}
