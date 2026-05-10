// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test that userspace can correctly populate Xen and generic CPUID
 * timing leaves using KVM_GET_TSC_KHZ and KVM_VCPU_TSC_SCALE.
 *
 * This validates that the removal of KVM's runtime Xen CPUID modification
 * doesn't break guests, because userspace has all the information needed.
 */
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#include <asm/pvclock-abi.h>

#define XEN_CPUID_BASE		0x40000100
#define XEN_CPUID_LEAF(n)	(XEN_CPUID_BASE + (n))
#define GENERIC_TIMING_LEAF	0x40000010

/* Values set by host, verified by guest */
static u32 expected_tsc_khz;
static u32 expected_bus_khz;
static u32 expected_tsc_mul;
static s8   expected_tsc_shift;
static u64 host_khz;

static void guest_code(void)
{
	u32 eax, ebx, ecx, edx;

	/* Check generic timing leaf 0x40000010 */
	__cpuid(GENERIC_TIMING_LEAF, 0, &eax, &ebx, &ecx, &edx);
	GUEST_ASSERT_EQ(eax, expected_tsc_khz);
	GUEST_ASSERT_EQ(ebx, expected_bus_khz);

	/* Check Xen leaf 3, sub-leaf 0: ECX = guest TSC frequency */
	__cpuid(XEN_CPUID_LEAF(3), 0, &eax, &ebx, &ecx, &edx);
	GUEST_ASSERT_EQ(ecx, expected_tsc_khz);

	/* Check Xen leaf 3, sub-leaf 1: ECX = mul, EDX = shift */
	__cpuid(XEN_CPUID_LEAF(3), 1, &eax, &ebx, &ecx, &edx);
	GUEST_ASSERT_EQ(ecx, expected_tsc_mul);
	GUEST_ASSERT_EQ((s8)edx, expected_tsc_shift);

	GUEST_SYNC(0);
}

static void add_cpuid_entry(struct kvm_vcpu *vcpu, u32 function,
			    u32 index, u32 eax, u32 ebx,
			    u32 ecx, u32 edx)
{
	struct kvm_cpuid2 *cpuid = vcpu->cpuid;
	struct kvm_cpuid_entry2 *entry;
	int n = cpuid->nent;

	cpuid = realloc(vcpu->cpuid,
			sizeof(*cpuid) + (n + 1) * sizeof(*entry));
	TEST_ASSERT(cpuid, "Failed to grow vCPU CPUID array");
	vcpu->cpuid = cpuid;
	cpuid->nent = n + 1;

	entry = &cpuid->entries[n];
	memset(entry, 0, sizeof(*entry));
	entry->function = function;
	entry->index = index;
	entry->flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
	entry->eax = eax;
	entry->ebx = ebx;
	entry->ecx = ecx;
	entry->edx = edx;
}

/*
 * Compute pvclock mul/shift from frequency, matching kvm_get_time_scale().
 */
static void compute_tsc_mul_shift(u64 tsc_hz, u32 *mul, s8 *shift)
{
	u64 scaled = 1000000000ULL;
	u64 base = tsc_hz;
	s32 s = 0;
	u32 base32;

	while (base > scaled * 2 || base >> 32) {
		base >>= 1;
		s--;
	}
	base32 = (u32)base;
	while (base32 <= scaled || scaled >> 32) {
		if (scaled >> 32 || base32 & (1U << 31))
			scaled >>= 1;
		else
			base32 <<= 1;
		s++;
	}
	*mul = (u32)((scaled << 32) / base32);
	*shift = (s8)s;
}

static void run_test(u64 tsc_khz)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	u32 effective_tsc_khz, effective_bus_khz;
	int bus_cycle_ns;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	if (tsc_khz) {
		pr_info("Testing at TSC frequency %lu kHz\n", tsc_khz);
		vcpu_ioctl(vcpu, KVM_SET_TSC_KHZ, (void *)(unsigned long)tsc_khz);
	} else {
		pr_info("Testing at native TSC frequency\n");
	}

	effective_tsc_khz = __vcpu_ioctl(vcpu, KVM_GET_TSC_KHZ, NULL);
	bus_cycle_ns = vm_check_cap(vm, KVM_CAP_X86_APIC_BUS_CYCLES_NS);
	effective_bus_khz = bus_cycle_ns > 0 ? 1000000 / bus_cycle_ns : 1000000;

	/* If scaling wasn't applied, skip this frequency */
	if (tsc_khz && effective_tsc_khz == host_khz) {
		pr_info("  TSC scaling not available, skipping\n");
		kvm_vm_free(vm);
		return;
	}

	pr_info("  Effective TSC: %u kHz, Bus: %u kHz\n", effective_tsc_khz, effective_bus_khz);

	/* Also exercise KVM_VCPU_TSC_SCALE if available */
	if (!__vcpu_has_device_attr(vcpu, KVM_VCPU_TSC_CTRL,
				    KVM_VCPU_TSC_SCALE)) {
		struct kvm_vcpu_tsc_scale scale;

		vcpu_device_attr_get(vcpu, KVM_VCPU_TSC_CTRL,
				     KVM_VCPU_TSC_SCALE, &scale);
		pr_info("  TSC scale: ratio=%llu frac_bits=%llu\n",
			scale.tsc_ratio, scale.tsc_frac_bits);

		/*
		 * Verify: applying the ratio to the host TSC frequency
		 * should give approximately the effective frequency.
		 */
		if (tsc_khz) {
			u64 computed = ((__uint128_t)host_khz * scale.tsc_ratio) >> scale.tsc_frac_bits;
			s64 diff = (s64)computed - (s64)effective_tsc_khz;

			TEST_ASSERT(diff >= -1 && diff <= 1,
				    "TSC_SCALE ratio mismatch: computed %lu vs effective %u (diff %ld)",
				    computed, effective_tsc_khz, diff);
		}
	}

	compute_tsc_mul_shift((u64)effective_tsc_khz * 1000,
			      &expected_tsc_mul, &expected_tsc_shift);

	expected_tsc_khz = effective_tsc_khz;
	expected_bus_khz = effective_bus_khz;

	sync_global_to_guest(vm, expected_tsc_khz);
	sync_global_to_guest(vm, expected_bus_khz);
	sync_global_to_guest(vm, expected_tsc_mul);
	sync_global_to_guest(vm, expected_tsc_shift);

	/* Populate CPUID leaves as a VMM would */
	add_cpuid_entry(vcpu, GENERIC_TIMING_LEAF, 0,
			effective_tsc_khz, effective_bus_khz, 0, 0);
	add_cpuid_entry(vcpu, XEN_CPUID_LEAF(3), 0,
			0, 0, effective_tsc_khz, 0);
	add_cpuid_entry(vcpu, XEN_CPUID_LEAF(3), 1,
			0, 0, expected_tsc_mul,
			(u32)(u8)expected_tsc_shift);

	vcpu_set_cpuid(vcpu);

	pr_info("  pvclock mul=%u shift=%d\n", expected_tsc_mul, expected_tsc_shift);

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);

	switch (get_ucall(vcpu, &uc)) {
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
		break;
	case UCALL_SYNC:
		break;
	default:
		TEST_FAIL("Unexpected ucall");
	}

	kvm_vm_free(vm);
}

int main(void)
{
	u64 freq;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	TEST_REQUIRE(sys_clocksource_is_based_on_tsc());

	/* Check KVM_VCPU_TSC_SCALE is supported (implies TSC scaling) */
	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	TEST_REQUIRE(!__vcpu_has_device_attr(vcpu, KVM_VCPU_TSC_CTRL,
					     KVM_VCPU_TSC_SCALE));
	host_khz = __vcpu_ioctl(vcpu, KVM_GET_TSC_KHZ, NULL);
	kvm_vm_free(vm);

	/* Native frequency */
	run_test(0);

	/* Scaled frequencies — skip if TSC scaling not available */
	for (freq = 1000000; freq <= 4000000; freq += 1000000) {
		if (freq == host_khz)
			continue;
		run_test(freq);
	}

	pr_info("PASS: All CPUID timing leaf tests passed\n");
	return 0;
}
