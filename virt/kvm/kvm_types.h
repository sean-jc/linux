/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __KVM_TYPES_INTERNAL_H__
#define __KVM_TYPES_INTERNAL_H__

#include <linux/bits.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/spinlock_types.h>

struct kvm_async_pf;
struct kvm_irq_routing_table;
struct kvm_memory_slot;

enum pfn_cache_usage {
	KVM_GUEST_USES_PFN = BIT(0),
	KVM_HOST_USES_PFN  = BIT(1),
	KVM_GUEST_AND_HOST_USE_PFN = KVM_GUEST_USES_PFN | KVM_HOST_USES_PFN,
};

struct gfn_to_hva_cache {
	u64 generation;
	gpa_t gpa;
	unsigned long hva;
	unsigned long len;
	struct kvm_memory_slot *memslot;
};

struct gfn_to_pfn_cache {
	u64 generation;
	gpa_t gpa;
	unsigned long uhva;
	struct kvm_memory_slot *memslot;
	struct kvm_vcpu *vcpu;
	struct list_head list;
	rwlock_t lock;
	struct mutex refresh_lock;
	void *khva;
	kvm_pfn_t pfn;
	enum pfn_cache_usage usage;
	bool active;
	bool valid;
};

/*
 * Memory caches are used to preallocate memory ahead of various MMU flows,
 * e.g. page fault handlers.  Gracefully handling allocation failures deep in
 * MMU flows is problematic, as is triggering reclaim, I/O, etc... while
 * holding MMU locks.  Note, these caches act more like prefetch buffers than
 * classical caches, i.e. objects are not returned to the cache on being freed.
 *
 * The @capacity field and @objects array are lazily initialized when the cache
 * is topped up (__kvm_mmu_topup_memory_cache()).
 */
struct kvm_mmu_memory_cache {
	int nobjs;
	gfp_t gfp_zero;
	gfp_t gfp_custom;
	struct kmem_cache *kmem_cache;
	int capacity;
	void **objects;
};

#define HALT_POLL_HIST_COUNT			32

struct kvm_vm_stat_generic {
	u64 remote_tlb_flush;
	u64 remote_tlb_flush_requests;
};

struct kvm_vcpu_stat_generic {
	u64 halt_successful_poll;
	u64 halt_attempted_poll;
	u64 halt_poll_invalid;
	u64 halt_wakeup;
	u64 halt_poll_success_ns;
	u64 halt_poll_fail_ns;
	u64 halt_wait_ns;
	u64 halt_poll_success_hist[HALT_POLL_HIST_COUNT];
	u64 halt_poll_fail_hist[HALT_POLL_HIST_COUNT];
	u64 halt_wait_hist[HALT_POLL_HIST_COUNT];
	u64 blocking;
};

#define KVM_STATS_NAME_SIZE	48

#endif /* __KVM_TYPES_INTERNAL_H__ */
