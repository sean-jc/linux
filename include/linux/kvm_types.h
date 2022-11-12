/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __KVM_TYPES_H__
#define __KVM_TYPES_H__

#include <linux/types.h>

struct kvm;
struct kvm_device_ops;
struct kvm_interrupt;
struct kvm_one_reg;
struct kvm_run;
struct kvm_userspace_memory_region;
struct kvm_vcpu;
struct kvm_vcpu_init;
struct kvm_memslots;

/*
 * Address types:
 *
 *  gva - guest virtual address
 *  gpa - guest physical address
 *  gfn - guest frame number
 *  hva - host virtual address
 *  hpa - host physical address
 *  hfn - host frame number
 */

typedef unsigned long  gva_t;
typedef u64            gpa_t;
typedef u64            gfn_t;

#define GPA_INVALID	(~(gpa_t)0)

typedef unsigned long  hva_t;
typedef u64            hpa_t;
typedef u64            hfn_t;

typedef hfn_t kvm_pfn_t;

#endif /* __KVM_TYPES_H__ */
