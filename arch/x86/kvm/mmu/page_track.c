// SPDX-License-Identifier: GPL-2.0-only
/*
 * Support KVM gust page tracking
 *
 * This feature allows us to track page access in guest. Currently, only
 * write access is tracked.
 *
 * Copyright(C) 2015 Intel Corporation.
 *
 * Author:
 *   Xiao Guangrong <guangrong.xiao@linux.intel.com>
 */

#include <linux/kvm_host.h>
#include <linux/rculist.h>

#include "mmu.h"
#include "mmu_internal.h"
#include "page_track.h"

bool kvm_page_track_write_tracking_enabled(struct kvm *kvm)
{
	return IS_ENABLED(CONFIG_KVM_EXTERNAL_WRITE_TRACKING) ||
	       !tdp_enabled || kvm_shadow_root_allocated(kvm);
}

void kvm_page_track_free_memslot(struct kvm_memory_slot *slot)
{
	kvfree(slot->arch.gfn_write_track);
	slot->arch.gfn_write_track = NULL;
}

static int __kvm_page_track_write_tracking_alloc(struct kvm_memory_slot *slot,
						 unsigned long npages)
{
	const size_t size = sizeof(*slot->arch.gfn_write_track);

	if (!slot->arch.gfn_write_track)
		slot->arch.gfn_write_track = __vcalloc(npages, size,
						       GFP_KERNEL_ACCOUNT);

	return slot->arch.gfn_write_track ? 0 : -ENOMEM;
}

int kvm_page_track_create_memslot(struct kvm *kvm,
				  struct kvm_memory_slot *slot,
				  unsigned long npages)
{
	if (!kvm_page_track_write_tracking_enabled(kvm))
		return 0;

	return __kvm_page_track_write_tracking_alloc(slot, npages);
}

int kvm_page_track_write_tracking_alloc(struct kvm_memory_slot *slot)
{
	return __kvm_page_track_write_tracking_alloc(slot, slot->npages);
}

static void update_gfn_write_track(struct kvm_memory_slot *slot, gfn_t gfn,
				   short count)
{
	int index, val;

	index = gfn_to_index(gfn, slot->base_gfn, PG_LEVEL_4K);

	val = slot->arch.gfn_write_track[index];

	if (WARN_ON(val + count < 0 || val + count > USHRT_MAX))
		return;

	slot->arch.gfn_write_track[index] += count;
}

/*
 * add guest page to the tracking pool so that corresponding access on that
 * page will be intercepted.
 *
 * It should be called under the protection both of mmu-lock and kvm->srcu
 * or kvm->slots_lock.
 *
 * @kvm: the guest instance we are interested in.
 * @slot: the @gfn belongs to.
 * @gfn: the guest page.
 */
void kvm_write_track_add_gfn(struct kvm *kvm, struct kvm_memory_slot *slot,
			     gfn_t gfn)
{
	if (WARN_ON(!kvm_page_track_write_tracking_enabled(kvm)))
		return;

	update_gfn_write_track(slot, gfn, 1);

	/*
	 * new track stops large page mapping for the
	 * tracked page.
	 */
	kvm_mmu_gfn_disallow_lpage(slot, gfn);

	if (kvm_mmu_slot_gfn_write_protect(kvm, slot, gfn, PG_LEVEL_4K))
		kvm_flush_remote_tlbs(kvm);
}
EXPORT_SYMBOL_GPL(kvm_write_track_add_gfn);

/*
 * remove the guest page from the tracking pool which stops the interception
 * of corresponding access on that page.
 *
 * It should be called under the protection both of mmu-lock and kvm->srcu
 * or kvm->slots_lock.
 *
 * @kvm: the guest instance we are interested in.
 * @slot: the @gfn belongs to.
 * @gfn: the guest page.
 */
void kvm_write_track_remove_gfn(struct kvm *kvm,
				struct kvm_memory_slot *slot, gfn_t gfn)
{
	if (WARN_ON(!kvm_page_track_write_tracking_enabled(kvm)))
		return;

	update_gfn_write_track(slot, gfn, -1);

	/*
	 * allow large page mapping for the tracked page
	 * after the tracker is gone.
	 */
	kvm_mmu_gfn_allow_lpage(slot, gfn);
}
EXPORT_SYMBOL_GPL(kvm_write_track_remove_gfn);

/*
 * check if the corresponding access on the specified guest page is tracked.
 */
bool kvm_gfn_is_write_tracked(struct kvm *kvm,
			      const struct kvm_memory_slot *slot, gfn_t gfn)
{
	int index;

	if (!slot)
		return false;

	if (!kvm_page_track_write_tracking_enabled(kvm))
		return false;

	index = gfn_to_index(gfn, slot->base_gfn, PG_LEVEL_4K);
	return !!READ_ONCE(slot->arch.gfn_write_track[index]);
}

void kvm_page_track_cleanup(struct kvm *kvm)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;
	cleanup_srcu_struct(&head->track_srcu);
}

int kvm_page_track_init(struct kvm *kvm)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;
	INIT_HLIST_HEAD(&head->track_notifier_list);
	return init_srcu_struct(&head->track_srcu);
}

/*
 * register the notifier so that event interception for the tracked guest
 * pages can be received.
 */
void
kvm_page_track_register_notifier(struct kvm *kvm,
				 struct kvm_page_track_notifier_node *n)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;

	write_lock(&kvm->mmu_lock);
	hlist_add_head_rcu(&n->node, &head->track_notifier_list);
	write_unlock(&kvm->mmu_lock);
}
EXPORT_SYMBOL_GPL(kvm_page_track_register_notifier);

/*
 * stop receiving the event interception. It is the opposed operation of
 * kvm_page_track_register_notifier().
 */
void
kvm_page_track_unregister_notifier(struct kvm *kvm,
				   struct kvm_page_track_notifier_node *n)
{
	struct kvm_page_track_notifier_head *head;

	head = &kvm->arch.track_notifier_head;

	write_lock(&kvm->mmu_lock);
	hlist_del_rcu(&n->node);
	write_unlock(&kvm->mmu_lock);
	synchronize_srcu(&head->track_srcu);
}
EXPORT_SYMBOL_GPL(kvm_page_track_unregister_notifier);

/*
 * Notify the node that write access is intercepted and write emulation is
 * finished at this time.
 *
 * The node should figure out if the written page is the one that node is
 * interested in by itself.
 */
void kvm_page_track_write(struct kvm_vcpu *vcpu, gpa_t gpa, const u8 *new,
			  int bytes)
{
	struct kvm_page_track_notifier_head *head;
	struct kvm_page_track_notifier_node *n;
	int idx;

	head = &vcpu->kvm->arch.track_notifier_head;

	if (hlist_empty(&head->track_notifier_list))
		return;

	idx = srcu_read_lock(&head->track_srcu);
	hlist_for_each_entry_srcu(n, &head->track_notifier_list, node,
				srcu_read_lock_held(&head->track_srcu))
		if (n->track_write)
			n->track_write(vcpu, gpa, new, bytes, n);
	srcu_read_unlock(&head->track_srcu, idx);
}

/*
 * Notify the node that memory slot is being removed or moved so that it can
 * drop write-protection for the pages in the memory slot.
 *
 * The node should figure out it has any write-protected pages in this slot
 * by itself.
 */
void kvm_page_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot)
{
	struct kvm_page_track_notifier_head *head;
	struct kvm_page_track_notifier_node *n;
	int idx;

	head = &kvm->arch.track_notifier_head;

	if (hlist_empty(&head->track_notifier_list))
		return;

	idx = srcu_read_lock(&head->track_srcu);
	hlist_for_each_entry_srcu(n, &head->track_notifier_list, node,
				srcu_read_lock_held(&head->track_srcu))
		if (n->track_flush_slot)
			n->track_flush_slot(kvm, slot, n);
	srcu_read_unlock(&head->track_srcu, idx);
}
