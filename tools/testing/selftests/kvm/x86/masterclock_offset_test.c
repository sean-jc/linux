// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test that KVM master clock mode works with different TSC offsets
 * as long as all vCPUs have the same TSC frequency.
 */
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#include <asm/pvclock-abi.h>

#define KVMCLOCK_GPA	0xc0000000ull
#define TSC_OFFSET	(1000000000ULL)

#define NR_VCPUS	3

/* Read the per-vCPU pvclocks in an order other than creation order. */
static const int vcpu_order[NR_VCPUS] = {0, 2, 1};

static u64 pvclock_calc(struct pvclock_vcpu_time_info *pvti, u64 guest_tsc)
{
	u64 delta = guest_tsc - pvti->tsc_timestamp;

	if (pvti->tsc_shift >= 0)
		delta <<= pvti->tsc_shift;
	else
		delta >>= -(int)pvti->tsc_shift;

	return pvti->system_time + ((__uint128_t)delta * pvti->tsc_to_system_mul >> 32);
}

static void guest_code(u64 pvti_gpa)
{
	wrmsr(MSR_KVM_SYSTEM_TIME_NEW, pvti_gpa | KVM_MSR_ENABLED);
	for (;;)
		GUEST_SYNC(0);
}

static void get_pvtis(struct kvm_vcpu **vcpus,
		      struct pvclock_vcpu_time_info *pvti)
{
	int i;

	for (i = 0; i < NR_VCPUS; i++) {
		int idx = vcpu_order[i];

		vcpu_get_clock_guest(vcpus[idx], &pvti[idx]);
		pr_info("vCPU %d: tsc_timestamp=%lu system_time=%lu "
			"mul=%u shift=%d flags=0x%x\n",
			idx, (unsigned long)pvti[idx].tsc_timestamp,
			(unsigned long)pvti[idx].system_time,
			pvti[idx].tsc_to_system_mul, pvti[idx].tsc_shift,
			pvti[idx].flags);
	}
}

/*
 * Read the host TSC once and feed it through vCPU 0's and vCPU 2's
 * pvclocks (adding each vCPU's TSC offset). Both must compute exactly
 * the same kvmclock value.
 */
static void assert_pvclocks_match(struct pvclock_vcpu_time_info *pvti,
				  u64 offset0, const char *what)
{
	u64 host_tsc, clk0, clk2;

	host_tsc = rdtsc();
	clk0 = pvclock_calc(&pvti[0], host_tsc + offset0);
	clk2 = pvclock_calc(&pvti[2], host_tsc + offset0 + TSC_OFFSET);

	pr_info("%s: kvmclock via vCPU 0: %lu ns, via vCPU 2: %lu ns\n",
		what, (unsigned long)clk0, (unsigned long)clk2);
	TEST_ASSERT(clk0 == clk2,
		    "%s: kvmclock from offset vCPUs should match exactly, "
		    "diff=%ld ns", what, (long)(clk2 - clk0));
}

static void test_masterclock_active(struct kvm_vm *vm,
				    struct kvm_clock_data *clock)
{
	memset(clock, 0, sizeof(*clock));
	vm_get_clock(vm, clock);
	pr_info("KVM_GET_CLOCK flags: 0x%x\n", clock->flags);
	TEST_ASSERT(clock->flags & KVM_CLOCK_HOST_TSC,
		    "Master clock should be active, flags=0x%x", clock->flags);
	TEST_ASSERT(clock->flags & KVM_CLOCK_TSC_STABLE,
		    "KVM_CLOCK_TSC_STABLE should be set, flags=0x%x",
		    clock->flags);
}

static void test_offset_consistency(struct kvm_vcpu **vcpus,
				    struct pvclock_vcpu_time_info *pvti,
				    u64 offset0)
{
	u64 gtsc0, gtsc1, gtsc2;

	get_pvtis(vcpus, pvti);

	/* Read guest TSCs: should see (0+OFF) < 2 < (1+OFF) */
	gtsc0 = vcpu_get_msr(vcpus[0], MSR_IA32_TSC);
	gtsc2 = vcpu_get_msr(vcpus[2], MSR_IA32_TSC);
	gtsc1 = vcpu_get_msr(vcpus[1], MSR_IA32_TSC);
	pr_info("Guest TSCs: vcpu0=%lu vcpu2=%lu vcpu1=%lu\n",
		(unsigned long)gtsc0, (unsigned long)gtsc2,
		(unsigned long)gtsc1);
	TEST_ASSERT(gtsc0 + TSC_OFFSET < gtsc2 && gtsc2 < gtsc1 + TSC_OFFSET,
		    "Expected (vcpu0+OFF) < vcpu2 < (vcpu1+OFF)");

	/* PVCLOCK_TSC_STABLE_BIT should NOT be set (offsets differ) */
	TEST_ASSERT(!(pvti[2].flags & PVCLOCK_TSC_STABLE_BIT),
		    "PVCLOCK_TSC_STABLE_BIT should NOT be set, flags=0x%x",
		    pvti[2].flags);

	/* Same mul/shift */
	TEST_ASSERT(pvti[0].tsc_to_system_mul == pvti[2].tsc_to_system_mul &&
		    pvti[0].tsc_shift == pvti[2].tsc_shift,
		    "All vCPUs should have same mul/shift");

	assert_pvclocks_match(pvti, offset0, "Initial");
}

#define ONE_HOUR_NS (3600ULL * NSEC_PER_SEC)

static void test_set_clock_consistency(struct kvm_vm *vm,
				       struct kvm_vcpu **vcpus,
				       struct pvclock_vcpu_time_info *pvti,
				       struct kvm_clock_data *clock,
				       u64 offset0)
{
	struct kvm_clock_data setclk = { .clock = clock->clock + ONE_HOUR_NS };
	u64 clk0;
	int i;

	/*
	 * Add an hour to the VM kvmclock via KVM_SET_CLOCK, run each
	 * vCPU to pick up the update, and check they're still in sync.
	 */
	vm_set_clock(vm, &setclk);

	/* Guest code does GUEST_SYNC then exits — run each to see update */
	for (i = 0; i < NR_VCPUS; i++) {
		vcpu_run(vcpus[vcpu_order[i]]);
		TEST_ASSERT_KVM_EXIT_REASON(vcpus[vcpu_order[i]], KVM_EXIT_IO);
	}

	get_pvtis(vcpus, pvti);

	TEST_ASSERT(pvti[0].system_time == pvti[2].system_time,
		    "system_time should still match after KVM_SET_CLOCK");

	assert_pvclocks_match(pvti, offset0, "After +1h");

	/* Verify the clock actually moved by ~1 hour */
	clk0 = pvclock_calc(&pvti[0], rdtsc() + offset0);
	TEST_ASSERT(clk0 > ONE_HOUR_NS,
		    "Clock should be > 1 hour after set, got %lu ns",
		    (unsigned long)clk0);
}

int main(void)
{
	struct pvclock_vcpu_time_info pvti[NR_VCPUS];
	struct kvm_vcpu *vcpus[NR_VCPUS];
	struct kvm_clock_data clock;
	struct kvm_vm *vm;
	u64 offset0;
	int nr_pages;
	int i;

	TEST_REQUIRE(sys_clocksource_is_based_on_tsc());

	vm = vm_create_with_vcpus(NR_VCPUS, guest_code, vcpus);

	TEST_REQUIRE(!__vcpu_has_device_attr(vcpus[0], KVM_VCPU_TSC_CTRL,
					     KVM_VCPU_TSC_OFFSET));

	nr_pages = vm_calc_num_guest_pages(VM_MODE_DEFAULT, getpagesize());
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    KVMCLOCK_GPA, 1, nr_pages, 0);
	virt_map(vm, KVMCLOCK_GPA, KVMCLOCK_GPA, nr_pages);

	/* Give each vCPU its own pvclock structure within the page */
	for (i = 0; i < NR_VCPUS; i++)
		vcpu_args_set(vcpus[i], 1, KVMCLOCK_GPA +
			      i * sizeof(struct pvclock_vcpu_time_info) * 2);

	/* Get vCPU 0's default offset and set vCPU 2's offset higher */
	offset0 = vcpu_get_tsc_offset(vcpus[0]);
	vcpu_set_tsc_offset(vcpus[2], offset0 + TSC_OFFSET);

	/* Run each vCPU to enable kvmclock (with offset already set) */
	for (i = 0; i < NR_VCPUS; i++) {
		vcpu_run(vcpus[i]);
		TEST_ASSERT_KVM_EXIT_REASON(vcpus[i], KVM_EXIT_IO);
	}

	test_masterclock_active(vm, &clock);
	test_offset_consistency(vcpus, pvti, offset0);
	pr_info("PASSED: pvclock consistent across offset vCPUs\n");

	test_set_clock_consistency(vm, vcpus, pvti, &clock, offset0);
	pr_info("PASSED: pvclock still consistent after KVM_SET_CLOCK +1h\n");

	kvm_vm_free(vm);
	return 0;
}
