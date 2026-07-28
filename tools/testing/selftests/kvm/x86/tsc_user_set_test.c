// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test that the first userspace write to MSR_IA32_TSC takes effect
 * precisely, and is not subjected to the 1-second "slop" heuristic
 * which is only supposed to apply between successive *userspace*
 * writes (kvm->arch.user_set_tsc).
 *
 * The kernel synchronizes the TSC internally when a vCPU is created
 * (and when its frequency is set). If any of those kernel-internal
 * paths incorrectly sets user_set_tsc, then the first genuine write
 * from userspace which happens to fall within 1 second of virtual
 * cycle time of the kernel's default generation is "corrected" to
 * match that generation instead of being honoured exactly. That
 * breaks the restore of a guest which has genuinely been running
 * for less than one second.
 *
 * Simulate exactly that: create a vCPU (kernel establishes a default
 * TSC generation starting near zero), then perform the first
 * host-initiated write with a value corresponding to ~500ms of guest
 * runtime. If the slop heuristic fires, the written value is snapped
 * back to the kernel's generation (near zero) and the TSC reads back
 * hundreds of milliseconds low.
 */
#include "kvm_util.h"
#include "processor.h"

int main(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	u64 freq_khz, t_write, t_read, slack_cycles;

	vm = vm_create_with_one_vcpu(&vcpu, NULL);

	freq_khz = __vcpu_ioctl(vcpu, KVM_GET_TSC_KHZ, NULL);
	TEST_ASSERT(freq_khz > 0, "KVM_GET_TSC_KHZ failed");

	/*
	 * The first user write: a guest TSC corresponding to 500ms of
	 * runtime. This is within 1s (of virtual cycle time) of the
	 * kernel's default generation, so it is exactly the case that
	 * the slop heuristic would destroy if it were (incorrectly)
	 * armed by the kernel's own internal TSC synchronization.
	 */
	t_write = freq_khz * 500ULL;		/* khz * ms = cycles */
	vcpu_set_msr(vcpu, MSR_IA32_TSC, t_write);

	t_read = vcpu_get_msr(vcpu, MSR_IA32_TSC);

	/*
	 * The TSC advances between the write and the read; allow a
	 * generous 100ms of test overhead. If the write was snapped to
	 * the kernel's default generation, the value read back is
	 * ~500ms low (i.e. below t_write), which is unambiguous.
	 */
	slack_cycles = freq_khz * 100ULL;

	TEST_ASSERT(t_read >= t_write,
		    "TSC went backwards from explicit write: wrote %lu, read %lu"
		    " (first userspace write was subjected to 1-second slop?)",
		    t_write, t_read);
	TEST_ASSERT(t_read - t_write < slack_cycles,
		    "TSC read back too far from written value: wrote %lu, read %lu",
		    t_write, t_read);

	kvm_vm_free(vm);
	return 0;
}
