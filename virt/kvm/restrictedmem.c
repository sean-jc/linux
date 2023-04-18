// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/falloc.h>
#include <linux/kvm_host.h>
#include <linux/pagemap.h>
#include <linux/sbitmap.h>
#include <linux/shmem_fs.h>

#include "kvm_mm.h"

struct kvm_rmem {
	struct rw_semaphore lock;
	struct kvm *kvm;
	const struct file_operations *backing_f_ops;
	const struct address_space_operations *backing_a_ops;
	struct xarray bindings;
};

static int kvm_rmem_release(struct inode *inode, struct file *file)
{
	struct kvm_rmem *rmem = inode->i_mapping->private_data;

	WARN_ON_ONCE(rmem->backing_f_ops->release);

	xa_destroy(&rmem->bindings);
	kfree(rmem);

	return 0;
}

static void kvm_rmem_invalidate_begin(struct kvm *kvm, struct kvm_rmem *rmem,
				      pgoff_t start, pgoff_t end)
{
	struct kvm_memory_slot *slot;
	unsigned long index;
	bool flush = false;
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	KVM_MMU_LOCK(kvm);

	kvm_mmu_invalidate_begin(kvm);

	xa_for_each_range(&rmem->bindings, index, slot, start, end - 1) {
		struct kvm_gfn_range gfn_range = {
			.start = slot->base_gfn + max(start, slot->restrictedmem.index),
			.end = slot->base_gfn + min(end, slot->restrictedmem.index + slot->npages),
			.slot = slot,
			.pte = __pte(0),
			.may_block = true,
		};
		kvm_mmu_invalidate_range_add(kvm, gfn_range.start, gfn_range.end);

		flush |= kvm_unmap_gfn_range(kvm, &gfn_range);
	}

	if (flush)
		kvm_flush_remote_tlbs(kvm);

	KVM_MMU_UNLOCK(kvm);
	srcu_read_unlock(&kvm->srcu, idx);
}

static void kvm_rmem_invalidate_end(struct kvm *kvm, struct kvm_rmem *rmem,
				    pgoff_t start, pgoff_t end)
{
	KVM_MMU_LOCK(kvm);
	if (xa_find(&rmem->bindings, &start, end - 1, XA_PRESENT))
		kvm_mmu_invalidate_end(kvm);
	KVM_MMU_UNLOCK(kvm);
}

static long kvm_rmem_punch_hole(struct file *file, int mode, loff_t offset,
				loff_t len)
{
	struct kvm_rmem *rmem = file->f_mapping->private_data;
	pgoff_t start = offset >> PAGE_SHIFT;
	pgoff_t end = (offset + len) >> PAGE_SHIFT;
	struct kvm *kvm = rmem->kvm;
	int ret;

	if (!PAGE_ALIGNED(offset) || !PAGE_ALIGNED(len))
		return -EINVAL;

	/*
	 * Bindings must stable across invalidation to ensure the start+end
	 * are balanced.
	 */
	down_read(&rmem->lock);

	kvm_rmem_invalidate_begin(kvm, rmem, start, end);

	ret = rmem->backing_f_ops->fallocate(file, mode, offset, len);

	kvm_rmem_invalidate_end(kvm, rmem, start, end);

	up_read(&rmem->lock);

	return ret;
}

static long kvm_rmem_fallocate(struct file *file, int mode, loff_t offset,
			       loff_t len)
{
	struct kvm_rmem *rmem = file->f_mapping->private_data;

	if (mode & FALLOC_FL_PUNCH_HOLE)
		return kvm_rmem_punch_hole(file, mode, offset, len);

	return rmem->backing_f_ops->fallocate(file, mode, offset, len);
}

static int kvm_rmem_migrate_folio(struct address_space *mapping,
				  struct folio *dst, struct folio *src,
				  enum migrate_mode mode)
{
	WARN_ON_ONCE(1);
	return -EINVAL;
}

static int kvm_rmem_error_page(struct address_space *mapping, struct page *page)
{
	struct kvm_rmem *rmem = mapping->private_data;
	struct kvm_memory_slot *slot;
	unsigned long index;
	pgoff_t start, end;
	gfn_t gfn;

	down_read(&rmem->lock);

	start = page->index;
	end = start + thp_nr_pages(page);

	xa_for_each_range(&rmem->bindings, index, slot, start, end - 1) {
		for (gfn = start; gfn < end; gfn++) {
			if (WARN_ON_ONCE(gfn < slot->base_gfn ||
					 gfn >= slot->base_gfn + slot->npages))
				continue;

			send_sig_mceerr(BUS_MCEERR_AR,
					(void __user *)gfn_to_hva_memslot(slot, gfn),
					PAGE_SHIFT, current);
		}
	}

	up_read(&rmem->lock);

	return rmem->backing_a_ops->error_remove_page(mapping, page);
}

static const struct file_operations kvm_restrictedmem_fops = {
	.release = kvm_rmem_release,
	.fallocate = kvm_rmem_fallocate,
};

static const struct address_space_operations kvm_restrictedmem_aops = {
	.dirty_folio = noop_dirty_folio,
#ifdef CONFIG_MIGRATION
	.migrate_folio	= kvm_rmem_migrate_folio,
#endif
	.error_remove_page = kvm_rmem_error_page,
};

static int kvm_rmem_create(struct kvm *kvm, struct vfsmount *mount)
{
	struct address_space *mapping;
	struct kvm_rmem *rmem;
	struct file *file;
	int fd, err;

	fd = get_unused_fd_flags(0);
	if (fd < 0)
		return fd;

	if (mount)
		file = shmem_file_setup_with_mnt(mount, "kvm:restrictedmem", 0, VM_NORESERVE);
	else
		file = shmem_file_setup("kvm:restrictedmem", 0, VM_NORESERVE);

	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_fd;
	}

	mapping = file->f_mapping;
	if (WARN_ON_ONCE(mapping->private_data)) {
		err = -EEXIST;
		goto err_file;
	}

	rmem = kzalloc(sizeof(*rmem), GFP_KERNEL);
	if (!rmem) {
		err = -ENOMEM;
		goto err_file;
	}

	xa_init(&rmem->bindings);
	init_rwsem(&rmem->lock);
	rmem->kvm = kvm;
	rmem->backing_f_ops = file->f_op;
	rmem->backing_a_ops = mapping->a_ops;

	file->f_mode |= FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE;
	file->f_flags |= O_LARGEFILE;
	file->f_op = &kvm_restrictedmem_fops;

	mapping->a_ops = &kvm_restrictedmem_aops;
	mapping_set_unevictable(mapping);
	mapping_set_unmovable(mapping);
	mapping_set_gfp_mask(mapping,
			     mapping_gfp_mask(mapping) & ~__GFP_MOVABLE);

	mapping->private_data = rmem;

	fd_install(fd, file);
	return fd;

err_file:
	fput(file);
err_fd:
	put_unused_fd(fd);
	return err;
}

static int kvm_rmem_create_with_mount(struct kvm *kvm, int mount_fd)
{
	struct vfsmount *mnt;
	struct path *path;
	struct fd f;
	int ret;

	f = fdget_raw(mount_fd);
	if (!f.file)
		return -EBADF;

	ret = -EINVAL;
	path = &f.file->f_path;
	if (path->dentry != path->mnt->mnt_root)
		goto err_file;

	/* Disallow bind-mounts that aren't bind-mounts of the whole filesystem. */
	mnt = path->mnt;
	if (mnt->mnt_root != mnt->mnt_sb->s_root)
		goto err_file;

	if (mnt->mnt_sb->s_magic != TMPFS_MAGIC)
		goto err_file;

	ret = mnt_want_write(mnt);
	if (ret)
		goto err_file;

	ret = kvm_rmem_create(kvm, mnt);

	mnt_drop_write(mnt);
err_file:
	fdput(f);
	return ret;
}

int kvm_restrictedmem_create(struct kvm *kvm, unsigned int flag, int mount_fd)
{
	if (mount_fd >= 0)
		return kvm_rmem_create_with_mount(kvm, mount_fd);

	return kvm_rmem_create(kvm, NULL);
}

int kvm_restrictedmem_bind(struct kvm *kvm, struct kvm_memory_slot *slot,
			   unsigned int fd, loff_t offset)
{
	unsigned long start, end;
	struct kvm_rmem *rmem;

	BUILD_BUG_ON(sizeof(gfn_t) != sizeof(slot->restrictedmem.index));

	if (offset < 0)
		return -EINVAL;

	slot->restrictedmem.file = fget(fd);
	if (!slot->restrictedmem.file)
		return -EINVAL;

	if (slot->restrictedmem.file->f_op != &kvm_restrictedmem_fops)
		goto err;

	rmem = slot->restrictedmem.file->f_mapping->private_data;

	if (rmem->kvm != kvm)
		goto err;

	down_write(&rmem->lock);

	start = offset >> PAGE_SHIFT;
	end = start + slot->npages;

	if (!xa_empty(&rmem->bindings) &&
	    xa_find(&rmem->bindings, &start, end - 1, XA_PRESENT)) {
		up_write(&rmem->lock);
		goto err;
	}

	xa_store_range(&rmem->bindings, start, end - 1, slot, GFP_KERNEL);
	up_write(&rmem->lock);

	slot->restrictedmem.index = start;
	return 0;

err:
	fput(slot->restrictedmem.file);
	slot->restrictedmem.file = NULL;
	return -EINVAL;
}

void kvm_restrictedmem_unbind(struct kvm_memory_slot *slot)
{
	unsigned long start = slot->restrictedmem.index;
	unsigned long end = start + slot->npages;
	struct kvm_rmem *rmem;

	if (WARN_ON_ONCE(!slot->restrictedmem.file))
		return;

	rmem = slot->restrictedmem.file->f_mapping->private_data;

	down_write(&rmem->lock);
	xa_store_range(&rmem->bindings, start, end - 1, NULL, GFP_KERNEL);
	synchronize_rcu();
	up_write(&rmem->lock);

	fput(slot->restrictedmem.file);
	slot->restrictedmem.file = NULL;
}


int kvm_restrictedmem_get_pfn(struct kvm *kvm, struct kvm_memory_slot *slot,
			      gfn_t gfn, kvm_pfn_t *pfn, int *order)
{
	pgoff_t offset = gfn - slot->base_gfn + slot->restrictedmem.index;
	struct file *file = slot->restrictedmem.file;
	struct kvm_rmem *rmem = file->f_mapping->private_data;
	struct folio *folio;
	struct page *page;
	int ret;

	if (WARN_ON_ONCE(xa_load(&rmem->bindings, offset) != slot))
		return -EINVAL;

	ret = shmem_get_folio(file_inode(file), offset, &folio, SGP_WRITE);
	if (ret)
		return ret;

	page = folio_file_page(folio, offset);

	*pfn = page_to_pfn(page);
	*order = thp_order(compound_head(page));

	SetPageUptodate(page);
	unlock_page(page);

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_restrictedmem_get_pfn);
