/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Helpers used for SEV guests
 *
 */
#ifndef SELFTEST_KVM_SEV_H
#define SELFTEST_KVM_SEV_H

#include <stdint.h>
#include <stdbool.h>

#include "kvm_util.h"

#define CPUID_MEM_ENC_LEAF 0x8000001f
#define CPUID_EBX_CBIT_MASK 0x3f

#define SEV_POLICY_NO_DBG	(1UL << 0)
#define SEV_POLICY_ES		(1UL << 2)

bool is_kvm_sev_supported(void);

void sev_vm_init(struct kvm_vm *vm);

struct kvm_vm *vm_sev_create_with_one_vcpu(uint32_t policy, void *guest_code,
					   struct kvm_vcpu **cpu);

#endif /* SELFTEST_KVM_SEV_H */
