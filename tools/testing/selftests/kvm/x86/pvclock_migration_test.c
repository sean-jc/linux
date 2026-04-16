// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test KVM clock precision across simulated live migration.
 *
 * Verifies that the documented TSC migration procedure (using
 * KVM_VCPU_TSC_OFFSET, KVM_VCPU_TSC_SCALE, KVM_GET_CLOCK, and
 * KVM_SET_CLOCK_GUEST) preserves the kvmclock's relationship to
 * CLOCK_MONOTONIC_RAW.
 *
 * The test:
 * 1. Creates a VM, runs the guest to enable kvmclock
 * 2. Does a PTP-like ABA measurement of kvmclock vs CLOCK_MONOTONIC_RAW
 * 3. Follows the documented migration procedure (same host, 1s pause)
 * 4. Does the same ABA measurement on the destination VM
 * 5. Verifies the kvmclock-vs-monotonic delta is preserved
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#include <asm/pvclock-abi.h>

#define KVMCLOCK_GPA	0xc0000000ULL

static void guest_code(void)
{
	wrmsr(MSR_KVM_SYSTEM_TIME_NEW, KVMCLOCK_GPA | 1);
	GUEST_SYNC(0);
	GUEST_SYNC(1);
}

static u64 read_kvmclock_ns(struct kvm_vm *vm)
{
	struct kvm_clock_data data = {};

	vm_get_clock(vm, &data);
	return data.clock;
}

static u64 pvclock_read_cycles(struct pvclock_vcpu_time_info *src,
				    u64 tsc)
{
	u64 delta = tsc - src->tsc_timestamp;
	u64 ns;

	if (src->tsc_shift >= 0)
		delta <<= src->tsc_shift;
	else
		delta >>= -(s32)src->tsc_shift;

	ns = (unsigned __int128)delta * src->tsc_to_system_mul >> 32;
	return src->system_time + ns;
}

/*
 * ABA measurement: read CLOCK_MONOTONIC_RAW, kvmclock, CLOCK_MONOTONIC_RAW.
 * Repeat 3 times, keep the reading with the smallest spread.
 */
static void aba_reading(struct kvm_vm *vm, u64 *lo, u64 *kvm_ns,
			u64 *hi)
{
	u64 best_spread = UINT64_MAX;
	int i;

	for (i = 0; i < 3; i++) {
		struct timespec ts1, ts2;
		u64 m1, m2, clk;

		clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
		clk = read_kvmclock_ns(vm);
		clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

		m1 = ts1.tv_sec * 1000000000ULL + ts1.tv_nsec;
		m2 = ts2.tv_sec * 1000000000ULL + ts2.tv_nsec;

		if (m2 - m1 < best_spread) {
			best_spread = m2 - m1;
			*lo = m1;
			*kvm_ns = clk;
			*hi = m2;
		}
	}
}

static struct kvm_vm *create_vm(struct kvm_vcpu **vcpu)
{
	struct kvm_vm *vm = vm_create_with_one_vcpu(vcpu, guest_code);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    KVMCLOCK_GPA, 1, 1, 0);
	virt_map(vm, KVMCLOCK_GPA, KVMCLOCK_GPA, 1);
	return vm;
}

int main(void)
{
	struct pvclock_vcpu_time_info pvti_src;
	struct kvm_clock_data clock_src, clock_dst;
	struct kvm_vcpu_tsc_scale scale_src, scale_dst;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	u64 mono_before, kvm_before, kvm_after;
	s64 delta_before;
	u64 ofs_src, tsc_src, tsc_dst, raw_dst, ofs_dst;
	u64 host_tsc_src, host_tsc_dst;
	u64 time_src, time_dst;
	s64 delta_t;
	u32 freq_khz = 1500000; /* 1.5 GHz — forces TSC scaling */

	TEST_REQUIRE(sys_clocksource_is_based_on_tsc());
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_TSC_CONTROL));

	/* === SOURCE SIDE === */
	pr_info("=== Source VM ===\n");
	vm = create_vm(&vcpu);

	/* Set guest TSC frequency (may trigger scaling) */
	vcpu_ioctl(vcpu, KVM_SET_TSC_KHZ, (void *)(unsigned long)freq_khz);

	/* Run guest to enable kvmclock */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);

	/* ABA measurement: kvmclock vs CLOCK_MONOTONIC_RAW */
	u64 src_mono_lo, src_mono_hi;
	aba_reading(vm, &src_mono_lo, &kvm_before, &src_mono_hi);
	mono_before = (src_mono_lo + src_mono_hi) / 2;
	delta_before = (s64)(kvm_before - mono_before);
	pr_info("  kvmclock - MONOTONIC_RAW = %" PRId64 " ns (±%" PRIu64 " ns)\n",
		delta_before, (src_mono_hi - src_mono_lo) / 2);

	/* Step 1: KVM_GET_CLOCK for atomic {host_tsc, realtime} */
	memset(&clock_src, 0, sizeof(clock_src));
	clock_src.flags = KVM_CLOCK_REALTIME;
	vm_get_clock(vm, &clock_src);
	host_tsc_src = clock_src.host_tsc;
	time_src = clock_src.realtime;

	/* Step 2: Save TSC offset and scale */
	ofs_src = vcpu_get_tsc_offset(vcpu);
	memset(&scale_src, 0, sizeof(scale_src));
	vcpu_device_attr_get(vcpu, KVM_VCPU_TSC_CTRL, KVM_VCPU_TSC_SCALE,
			     &scale_src);

	/* Compute guest TSC at Tsrc */
	if (scale_src.tsc_frac_bits)
		tsc_src = ((unsigned __int128)host_tsc_src * scale_src.tsc_ratio
			   >> scale_src.tsc_frac_bits) + ofs_src;
	else
		tsc_src = host_tsc_src + ofs_src;

	/* Step 3: KVM_GET_CLOCK_GUEST */
	vcpu_get_clock_guest(vcpu, &pvti_src);

	pr_info("  TSC freq=%u kHz, offset=%" PRId64 "\n", freq_khz, (s64)ofs_src);

	kvm_vm_release(vm);

	/* === PAUSE (simulate migration) === */
	pr_info("=== Pausing 1 second ===\n");
	sleep(1);

	/* === DESTINATION SIDE === */
	pr_info("=== Destination VM ===\n");
	vm = create_vm(&vcpu);

	/* Step 4: KVM_SET_TSC_KHZ */
	vcpu_ioctl(vcpu, KVM_SET_TSC_KHZ, (void *)(unsigned long)freq_khz);

	/* Step 5: KVM_GET_CLOCK for atomic {host_tsc, realtime} pair.
	 * Master clock is active from vCPU creation.
	 */
	memset(&clock_dst, 0, sizeof(clock_dst));
	vm_get_clock(vm, &clock_dst);
	host_tsc_dst = clock_dst.host_tsc;
	time_dst = clock_dst.realtime;

	/* Step 6: ΔT */
	delta_t = (s64)(time_dst - time_src);

	/* Step 7: Compute destination offset */
	memset(&scale_dst, 0, sizeof(scale_dst));
	vcpu_device_attr_get(vcpu, KVM_VCPU_TSC_CTRL, KVM_VCPU_TSC_SCALE,
			     &scale_dst);

	tsc_dst = tsc_src + (u64)((s64)freq_khz * delta_t / 1000000LL);

	if (scale_dst.tsc_frac_bits)
		raw_dst = (unsigned __int128)host_tsc_dst * scale_dst.tsc_ratio
			  >> scale_dst.tsc_frac_bits;
	else
		raw_dst = host_tsc_dst;

	ofs_dst = tsc_dst - raw_dst;

	/*
	 * The TSC offset delta introduced by using CLOCK_REALTIME to
	 * estimate elapsed time. On same host, the correct offset is
	 * ofs_src; the difference is the CLOCK_REALTIME-vs-TSC error.
	 */
	s64 tsc_ofs_delta = (s64)(ofs_dst - ofs_src);
	s64 tsc_ofs_delta_ns = tsc_ofs_delta * 1000000LL / freq_khz;
	pr_info("  Destination TSC offset=%" PRId64
		", imprecision from CLOCK_REALTIME: %" PRId64 " cycles = %"
		PRId64 " ns\n", (s64)ofs_dst, tsc_ofs_delta, tsc_ofs_delta_ns);

	/* Set TSC offset */
	vcpu_set_tsc_offset(vcpu, ofs_dst);

	/* Step 8: KVM_SET_CLOCK_GUEST */
	vcpu_set_clock_guest(vcpu, &pvti_src);

	/* Run guest to update pvclock page on destination */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);

	/* ABA measurement on destination */
	u64 mono_lo, mono_hi;
	aba_reading(vm, &mono_lo, &kvm_after, &mono_hi);

	/*
	 * The kvmclock is tied to the guest TSC via SET_CLOCK_GUEST.
	 * The guest TSC is offset from the correct value by tsc_ofs_delta_ns
	 * (due to CLOCK_REALTIME imprecision). So the kvmclock should be
	 * offset from CLOCK_MONOTONIC_RAW by exactly:
	 *   (original delta) + tsc_ofs_delta_ns
	 *
	 * The "original delta" has uncertainty from the source ABA spread,
	 * and the measurement has uncertainty from the destination ABA spread.
	 * Verify the expected value falls within the combined bounds.
	 */
	s64 delta_before_lo = (s64)(kvm_before - src_mono_hi);
	s64 delta_before_hi = (s64)(kvm_before - src_mono_lo);
	s64 expected_lo = delta_before_lo + tsc_ofs_delta_ns;
	s64 expected_hi = delta_before_hi + tsc_ofs_delta_ns;
	s64 actual_lo = (s64)(kvm_after - mono_hi);
	s64 actual_hi = (s64)(kvm_after - mono_lo);

	/* Show the shift relative to the source measurement */
	s64 expected_mid = tsc_ofs_delta_ns;
	s64 expected_err = (s64)(src_mono_hi - src_mono_lo) / 2;
	s64 actual_mid = ((actual_lo + actual_hi) / 2) - delta_before;
	s64 actual_err = (s64)(mono_hi - mono_lo) / 2;
	pr_info("  kvmclock-mono shift: expected %" PRId64 " ns (±%" PRId64
		"), measured %" PRId64 " ns (±%" PRId64 ")\n",
		expected_mid, expected_err, actual_mid, actual_err);

	/* The ranges must overlap */
	TEST_ASSERT(expected_hi >= actual_lo && expected_lo <= actual_hi,
		    "Ranges don't overlap: expected [%" PRId64 ", %" PRId64
		    "] measured [%" PRId64 ", %" PRId64 "]",
		    expected_lo, expected_hi, actual_lo, actual_hi);

	/*
	 * Direct pvclock verification: read the destination pvclock page
	 * and verify that computing kvmclock from pvti_src and pvti_dst
	 * at the same guest TSC gives the same result.
	 *
	 * Get an atomic {host_tsc, kvmclock} pair, scale host_tsc to
	 * guest TSC using KVM_VCPU_TSC_SCALE, then compute kvmclock
	 * from both pvclock structs.
	 */
	struct kvm_clock_data clock_now = {};
	vm_get_clock(vm, &clock_now);

	struct pvclock_vcpu_time_info *pvti_dst = addr_gpa2hva(vm, KVMCLOCK_GPA);
	u64 host_tsc_now = clock_now.host_tsc;
	u64 guest_tsc_now;

	if (scale_dst.tsc_frac_bits)
		guest_tsc_now = ((unsigned __int128)host_tsc_now *
				 scale_dst.tsc_ratio >> scale_dst.tsc_frac_bits)
				+ ofs_dst;
	else
		guest_tsc_now = host_tsc_now + ofs_dst;

	u64 clk_from_src = pvclock_read_cycles(&pvti_src, guest_tsc_now);
	u64 clk_from_dst = pvclock_read_cycles(pvti_dst, guest_tsc_now);
	s64 pvclock_delta = (s64)(clk_from_src - clk_from_dst);

	pr_info("  Pvclock direct: src=%" PRIu64 " dst=%" PRIu64
		" delta=%" PRId64 " ns\n", clk_from_src, clk_from_dst, pvclock_delta);
	pr_info("  KVM_GET_CLOCK:  %" PRIu64 " ns\n", (u64)clock_now.clock);

	TEST_ASSERT(pvclock_delta >= -2 && pvclock_delta <= 2,
		    "pvclock src vs dst disagree by %" PRId64 " ns", pvclock_delta);

	/*
	 * Tight ABA: compare pvclock_read() directly (no ioctl) against
	 * CLOCK_MONOTONIC_RAW. The spread should be much smaller since
	 * there's no syscall between the two clock_gettime calls — just
	 * rdtsc + userspace mul/shift.
	 */
	u64 tight_mono_lo = 0, tight_mono_hi = 0, tight_kvm = 0;
	u64 tight_best_spread = UINT64_MAX;
	for (int i = 0; i < 3; i++) {
		struct timespec ts1, ts2;
		u64 m1, m2, tsc, clk;

		clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
		tsc = rdtsc();
		clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

		m1 = ts1.tv_sec * 1000000000ULL + ts1.tv_nsec;
		m2 = ts2.tv_sec * 1000000000ULL + ts2.tv_nsec;

		/* Scale host TSC to guest TSC */
		if (scale_dst.tsc_frac_bits)
			tsc = ((unsigned __int128)tsc * scale_dst.tsc_ratio
			       >> scale_dst.tsc_frac_bits) + ofs_dst;
		else
			tsc += ofs_dst;

		clk = pvclock_read_cycles(pvti_dst, tsc);

		if (m2 - m1 < tight_best_spread) {
			tight_best_spread = m2 - m1;
			tight_mono_lo = m1;
			tight_mono_hi = m2;
			tight_kvm = clk;
		}
	}
	pr_info("  Tight ABA spread: %" PRIu64 " ns (best of 3)\n", tight_best_spread);

	s64 tight_expected_lo = delta_before_lo + tsc_ofs_delta_ns;
	s64 tight_expected_hi = delta_before_hi + tsc_ofs_delta_ns;
	s64 tight_actual_lo = (s64)(tight_kvm - tight_mono_hi);
	s64 tight_actual_hi = (s64)(tight_kvm - tight_mono_lo);
	s64 tight_actual_mid = ((tight_actual_lo + tight_actual_hi) / 2) - delta_before;
	s64 tight_actual_err = (s64)(tight_mono_hi - tight_mono_lo) / 2;

	pr_info("  Tight kvmclock-mono shift: expected %" PRId64
		" ns (±%" PRId64 "), measured %" PRId64 " ns (±%" PRId64 ")\n",
		expected_mid, expected_err, tight_actual_mid, tight_actual_err);

	TEST_ASSERT(tight_expected_hi >= tight_actual_lo &&
		    tight_expected_lo <= tight_actual_hi,
		    "Tight ABA ranges don't overlap");

	kvm_vm_release(vm);
	pr_info("PASS: kvmclock offset matches TSC delta from CLOCK_REALTIME"
		" (%" PRId64 " ns) within ABA bounds\n", tsc_ofs_delta_ns);
	return 0;
}
