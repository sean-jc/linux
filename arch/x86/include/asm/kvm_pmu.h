/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_KVM_PMU_H
#define _ASM_X86_KVM_PMU_H

#include <linux/types.h>

struct kvm_pmu_state {
	u64 ds_area;
	u64 pebs_data_cfg;
	u64 host_cross_mapped_mask;
};

#endif /* _ASM_X86_KVM_PMU_H */
