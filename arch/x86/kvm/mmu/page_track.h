/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_PAGE_TRACK_H
#define __KVM_X86_PAGE_TRACK_H

#include <asm/kvm_page_track.h>

int kvm_page_track_init(struct kvm *kvm);
void kvm_page_track_cleanup(struct kvm *kvm);

bool kvm_page_track_write_tracking_enabled(struct kvm *kvm);
int kvm_page_track_write_tracking_alloc(struct kvm_memory_slot *slot);

void kvm_page_track_free_memslot(struct kvm_memory_slot *slot);
int kvm_page_track_create_memslot(struct kvm *kvm,
				  struct kvm_memory_slot *slot,
				  unsigned long npages);

bool kvm_gfn_is_write_tracked(struct kvm *kvm,
			      const struct kvm_memory_slot *slot, gfn_t gfn);

void kvm_page_track_write(struct kvm_vcpu *vcpu, gpa_t gpa, const u8 *new,
			  int bytes);
void kvm_page_track_flush_slot(struct kvm *kvm, struct kvm_memory_slot *slot);

#endif /* __KVM_X86_PAGE_TRACK_H */
