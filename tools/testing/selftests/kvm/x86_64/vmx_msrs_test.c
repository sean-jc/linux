// SPDX-License-Identifier: GPL-2.0-only
/*
 * VMX control MSR test
 *
 * Copyright (C) 2022 Google LLC.
 *
 * Tests for KVM ownership of bits in the VMX entry/exit control MSRs. Checks
 * that KVM will set owned bits where appropriate, and will not if
 * KVM_X86_QUIRK_TWEAK_VMX_CTRL_MSRS is disabled.
 */
#include <linux/bitmap.h>

#include "kvm_util.h"
#include "vmx.h"

#define SUBTEST_REQUIRE(f)					\
	if (!(f)) {						\
		print_skip("Requirement not met: %s", #f);	\
		return;						\
	}

static bool vmx_has_ctrl(struct kvm_vcpu *vcpu, uint32_t msr, uint32_t ctrl_mask)
{
	return (vcpu_get_msr(vcpu, msr) >> 32) & ctrl_mask;
}

static void test_vmx_ctrl_msr(struct kvm_vcpu *vcpu,
			      uint32_t msr, uint64_t ctrl_mask,
			      bool quirk_enabled, bool feature_enabled)
{
	uint64_t ctrl_allowed1 = ctrl_mask << 32;
	uint64_t val = vcpu_get_msr(vcpu, msr);

	/*
	 * If the quirk is enabled, KVM should have modified the MSR when the
	 * guest's CPUID was set.  Don't assert anything when the quirk is
	 * disabled, the value of the MSR is not known (it could be made known,
	 * but it gets messy and the added value is minimal).
	 */
	TEST_ASSERT(!quirk_enabled || (!!(val & ctrl_allowed1) == feature_enabled),
		    "KVM owns the ctrl when the quirk is enabled, want 0x%lx, got 0x%lx",
		    feature_enabled ? ctrl_allowed1 : 0, val & ctrl_allowed1);

	val |= ctrl_allowed1;
	vcpu_set_msr(vcpu, msr, val);

	val = vcpu_get_msr(vcpu, msr);
	if (quirk_enabled)
		TEST_ASSERT(!!(val & ctrl_allowed1) == feature_enabled,
			    "KVM owns the ctrl when the quirk is enabled, want 0x%lx, got 0x%lx",
			    feature_enabled ? ctrl_allowed1 : 0, val & ctrl_allowed1);
	else
		TEST_ASSERT(val & ctrl_allowed1,
			    "KVM shouldn't clear the ctrl when the quirk is disabled");

	val &= ~ctrl_allowed1;
	vcpu_set_msr(vcpu, msr, val);

	val = vcpu_get_msr(vcpu, msr);
	if (quirk_enabled)
		TEST_ASSERT(!!(val & ctrl_allowed1) == feature_enabled,
			    "KVM owns the ctrl when the quirk is enabled, want 0x%lx, got 0x%lx",
			    feature_enabled ? ctrl_allowed1 : 0, val & ctrl_allowed1);
	else
		TEST_ASSERT(!(val & ctrl_allowed1),
			    "KVM shouldn't set the ctrl when the quirk is disabled");
}

static void test_vmx_ctrl_msrs_pair(struct kvm_vcpu *vcpu,
				    bool quirk_enabled, bool feature_enabled,
				    uint32_t entry_msr, uint64_t entry_mask,
				    uint32_t exit_msr, uint64_t exit_mask)
{
	test_vmx_ctrl_msr(vcpu, entry_msr, entry_mask, quirk_enabled, feature_enabled);
	test_vmx_ctrl_msr(vcpu, exit_msr, exit_mask, quirk_enabled, feature_enabled);
}

static void test_vmx_ctrls(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
			   uint64_t entry_ctrl, uint64_t exit_ctrl)
{
	/*
	 * KVM's quirky behavior only exists for PERF_GLOBAL_CTRL and BNDCFGS,
	 * any attempt to extend KVM's quirky behavior must be met with fierce
	 * resistance!
	 */
	TEST_ASSERT(entry_ctrl == VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL ||
		    entry_ctrl == VM_ENTRY_LOAD_BNDCFGS,
		    "Don't let KVM expand its quirk beyond PERF_GLOBAL_CTRL and BNDCFSG");

	SUBTEST_REQUIRE(vmx_has_ctrl(vcpu, MSR_IA32_VMX_TRUE_ENTRY_CTLS, entry_ctrl));
	SUBTEST_REQUIRE(vmx_has_ctrl(vcpu, MSR_IA32_VMX_TRUE_EXIT_CTLS, exit_ctrl));

	/*
	 * Test that, when the quirk is enabled, KVM sets/clears the VMX MSR
	 * bits based on whether or not the feature is exposed to the guest.
	 */
	test_vmx_ctrl_msrs_pair(vcpu, true, true,
				MSR_IA32_VMX_TRUE_ENTRY_CTLS, entry_ctrl,
				MSR_IA32_VMX_TRUE_EXIT_CTLS, exit_ctrl);

	/* Hide the feature in CPUID. */
	if (entry_ctrl == VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL)
		vcpu_clear_cpuid_entry(vcpu, 0xa);
	else
		vcpu_clear_cpuid_feature(vcpu, X86_FEATURE_MPX);

	test_vmx_ctrl_msrs_pair(vcpu, true, false,
				MSR_IA32_VMX_TRUE_ENTRY_CTLS, entry_ctrl,
				MSR_IA32_VMX_TRUE_EXIT_CTLS, exit_ctrl);

	/*
	 * Disable the quirk, giving userspace control of the VMX MSRs.  KVM
	 * should not touch the MSR, i.e. should allow hiding the control when
	 * a vPMU is supported, and should allow exposing the control when a
	 * vPMU is not supported.
	 */
	vm_enable_cap(vm, KVM_CAP_DISABLE_QUIRKS2, KVM_X86_QUIRK_TWEAK_VMX_MSRS);

	test_vmx_ctrl_msrs_pair(vcpu, false, false,
				MSR_IA32_VMX_TRUE_ENTRY_CTLS, entry_ctrl,
				MSR_IA32_VMX_TRUE_EXIT_CTLS, exit_ctrl);

	/* Restore the full CPUID to expose the feature to the guest. */
	vcpu_init_cpuid(vcpu, kvm_get_supported_cpuid());
	test_vmx_ctrl_msrs_pair(vcpu, false, true,
				MSR_IA32_VMX_TRUE_ENTRY_CTLS, entry_ctrl,
				MSR_IA32_VMX_TRUE_EXIT_CTLS, exit_ctrl);

	vm_enable_cap(vm, KVM_CAP_DISABLE_QUIRKS2, 0);
}

static void load_perf_global_ctrl_test(struct kvm_vm *vm, struct kvm_vcpu *vcpu)
{
	SUBTEST_REQUIRE(kvm_get_cpuid_max_basic() >= 0xa);

	test_vmx_ctrls(vm, vcpu, VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL,
		       VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL);
}

static void load_and_clear_bndcfgs_test(struct kvm_vm *vm, struct kvm_vcpu *vcpu)
{
	SUBTEST_REQUIRE(kvm_cpu_has(X86_FEATURE_MPX));

	test_vmx_ctrls(vm, vcpu, VM_ENTRY_LOAD_BNDCFGS, VM_EXIT_CLEAR_BNDCFGS);
}

static void cr4_reserved_bit_test(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
				  uint64_t cr4_bit,
				  struct kvm_x86_cpu_feature feature)
{
	uint64_t val;
	int r;

	if (!kvm_cpu_has(feature))
		return;

	vcpu_set_cpuid_feature(vcpu, feature);
	val = vcpu_get_msr(vcpu, MSR_IA32_VMX_CR4_FIXED1);
	TEST_ASSERT(val & cr4_bit,
		    "KVM should set CR4 bit when quirk and feature are enabled");

	vcpu_clear_cpuid_feature(vcpu, feature);
	val = vcpu_get_msr(vcpu, MSR_IA32_VMX_CR4_FIXED1);
	TEST_ASSERT(!(val & cr4_bit),
		    "KVM should clear CR4 bit when quirk and feature are enabled");

	r = _vcpu_set_msr(vcpu, MSR_IA32_VMX_CR4_FIXED1, val);
	TEST_ASSERT(r == 0, "Writing CR4_FIXED1 should fail when quirk is enabled");

	vm_enable_cap(vm, KVM_CAP_DISABLE_QUIRKS2, KVM_X86_QUIRK_TWEAK_VMX_MSRS);

	val &= ~cr4_bit;
	vcpu_set_msr(vcpu, MSR_IA32_VMX_CR4_FIXED1, val);

	vcpu_set_cpuid_feature(vcpu, feature);
	TEST_ASSERT(!(val & cr4_bit),
		    "KVM shouldn't set CR4 bit when quirk is disabled");

	val |= cr4_bit;
	vcpu_clear_cpuid_feature(vcpu, feature);
	TEST_ASSERT(val & cr4_bit,
		    "KVM shouldn't clear CR4 bit when quirk is disabled");

	vm_enable_cap(vm, KVM_CAP_DISABLE_QUIRKS2, 0);
}

static void cr4_reserved_bits_test(struct kvm_vm *vm, struct kvm_vcpu *vcpu)
{
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_VME,        X86_FEATURE_VME);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_PVI,        X86_FEATURE_VME);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_TSD,        X86_FEATURE_TSC);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_DE,         X86_FEATURE_DE);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_PSE,        X86_FEATURE_PSE);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_PAE,        X86_FEATURE_PAE);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_MCE,        X86_FEATURE_MCE);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_PGE,        X86_FEATURE_PGE);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_OSFXSR,     X86_FEATURE_FXSR);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_OSXMMEXCPT, X86_FEATURE_XMM);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_VMXE,       X86_FEATURE_VMX);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_SMXE,       X86_FEATURE_SMX);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_PCIDE,      X86_FEATURE_PCID);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_OSXSAVE,    X86_FEATURE_XSAVE);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_FSGSBASE,   X86_FEATURE_FSGSBASE);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_SMEP,       X86_FEATURE_SMEP);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_SMAP,       X86_FEATURE_SMAP);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_PKE,        X86_FEATURE_PKU);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_UMIP,       X86_FEATURE_UMIP);
	cr4_reserved_bit_test(vm, vcpu, X86_CR4_LA57,       X86_FEATURE_LA57);
}

static void vmx_fixed1_msr_test(struct kvm_vcpu *vcpu, uint32_t msr_index,
				  uint64_t mask)
{
	uint64_t val = vcpu_get_msr(vcpu, msr_index);
	uint64_t bit;

	mask &= val;

	for_each_set_bit(bit, &mask, 64) {
		vcpu_set_msr(vcpu, msr_index, val & ~BIT_ULL(bit));
		vcpu_set_msr(vcpu, msr_index, val);
	}
}

static void vmx_fixed0_msr_test(struct kvm_vcpu *vcpu, uint32_t msr_index,
				uint64_t mask)
{
	uint64_t val = vcpu_get_msr(vcpu, msr_index);
	uint64_t bit;

	mask = ~mask | val;

	for_each_clear_bit(bit, &mask, 64) {
		vcpu_set_msr(vcpu, msr_index, val | BIT_ULL(bit));
		vcpu_set_msr(vcpu, msr_index, val);
	}
}

static void vmx_fixed0and1_msr_test(struct kvm_vcpu *vcpu, uint32_t msr_index)
{
	vmx_fixed0_msr_test(vcpu, msr_index, GENMASK_ULL(31, 0));
	vmx_fixed1_msr_test(vcpu, msr_index, GENMASK_ULL(63, 32));
}

static void vmx_save_restore_msrs_test(struct kvm_vcpu *vcpu)
{
	vcpu_set_msr(vcpu, MSR_IA32_VMX_VMCS_ENUM, 0);
	vcpu_set_msr(vcpu, MSR_IA32_VMX_VMCS_ENUM, -1ull);

	vmx_fixed1_msr_test(vcpu, MSR_IA32_VMX_BASIC,
			    BIT_ULL(49) | BIT_ULL(54) | BIT_ULL(55));

	vmx_fixed1_msr_test(vcpu, MSR_IA32_VMX_BASIC,
			    BIT_ULL(5) | GENMASK_ULL(8, 6) | BIT_ULL(14) |
			    BIT_ULL(15) | BIT_ULL(28) | BIT_ULL(29) | BIT_ULL(30));

	vmx_fixed0_msr_test(vcpu, MSR_IA32_VMX_CR0_FIXED0, -1ull);
	vmx_fixed1_msr_test(vcpu, MSR_IA32_VMX_CR0_FIXED1, -1ull);
	vmx_fixed0_msr_test(vcpu, MSR_IA32_VMX_CR4_FIXED0, -1ull);
	vmx_fixed1_msr_test(vcpu, MSR_IA32_VMX_CR4_FIXED1, -1ull);
	vmx_fixed0and1_msr_test(vcpu, MSR_IA32_VMX_PROCBASED_CTLS2);
	vmx_fixed1_msr_test(vcpu, MSR_IA32_VMX_EPT_VPID_CAP, -1ull);
	vmx_fixed0and1_msr_test(vcpu, MSR_IA32_VMX_TRUE_PINBASED_CTLS);
	vmx_fixed0and1_msr_test(vcpu, MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
	vmx_fixed0and1_msr_test(vcpu, MSR_IA32_VMX_TRUE_EXIT_CTLS);
	vmx_fixed0and1_msr_test(vcpu, MSR_IA32_VMX_TRUE_ENTRY_CTLS);
	vmx_fixed1_msr_test(vcpu, MSR_IA32_VMX_VMFUNC, -1ull);
}

int main(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_DISABLE_QUIRKS2));
	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_VMX));

	/* No need to actually do KVM_RUN, thus no guest code. */
	vm = vm_create_with_one_vcpu(&vcpu, NULL);

	load_perf_global_ctrl_test(vm, vcpu);
	load_and_clear_bndcfgs_test(vm, vcpu);
	cr4_reserved_bits_test(vm, vcpu);
	vmx_save_restore_msrs_test(vcpu);

	kvm_vm_free(vm);
}
