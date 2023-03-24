// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <stdint.h>
#include <stdbool.h>

#include "kvm_util.h"
#include "svm_util.h"
#include "linux/psp-sev.h"
#include "processor.h"
#include "sev.h"

#define SEV_FW_REQ_VER_MAJOR 0
#define SEV_FW_REQ_VER_MINOR 17

enum sev_guest_state {
	SEV_GSTATE_UNINIT = 0,
	SEV_GSTATE_LUPDATE,
	SEV_GSTATE_LSECRET,
	SEV_GSTATE_RUNNING,
};

static void sev_ioctl(int cmd, void *data)
{
	int sev_fd = open_sev_dev_path_or_exit();
	struct sev_issue_cmd arg {
		.cmd = cmd,
		.data = (unsigned long)data,
	};

	kvm_ioctl(sev_fd, SEV_ISSUE_CMD, &arg);
	close(sev_fd);
}

static void kvm_sev_ioctl(struct kvm_vm *vm, int cmd, void *data)
{
	struct kvm_sev_cmd sev_cmd = {
		.id = cmd,
		.sev_fd = vm->sev_fd,
		.data = (unsigned long)data,
	};

	vm_ioctl(vm, KVM_MEMORY_ENCRYPT_OP, &sev_cmd);
}

static void sev_register_encrypted_memory(struct kvm_vm *vm,
					  struct userspace_mem_region *region)
{
	struct kvm_enc_region range = {
		.addr = region->region.userspace_addr,
		.size = region->region.memory_size,
	};

	vm_ioctl(vm, KVM_MEMORY_ENCRYPT_REG_REGION, &range);
}

static void sev_launch_update_data(struct kvm_vm *vm, vm_paddr_t gpa,
				   uint64_t size)
{
	struct kvm_sev_launch_update_data update_data = {
		.uaddr = (unsigned long)addr_gpa2hva(vm, gpa),
		.len = size,
	};

	kvm_sev_ioctl(vm, KVM_SEV_LAUNCH_UPDATE_DATA, &update_data);
}

/*
 * sparsebit_next_clear() can return 0 if [x, 2**64-1] are all set, and the
 * -1 would then cause an underflow back to 2**64 - 1. This is expected and
 * correct.
 *
 * If the last range in the sparsebit is [x, y] and we try to iterate,
 * sparsebit_next_set() will return 0, and sparsebit_next_clear() will try
 * and find the first range, but that's correct because the condition
 * expression would cause us to quit the loop.
 */
static void encrypt_region(struct kvm_vm *vm, struct userspace_mem_region *region)
{
	const struct sparsebit *protected_phy_pages = region->protected_phy_pages;
	const vm_paddr_t gpa_base = region->region.guest_phys_addr;
	const sparsebit_idx_t lowest_page_in_region = gpa_base >> vm->page_shift;
	sparsebit_idx_t i, j;

	if (!sparsebit_any_set(protected_phy_pages))
		return;

	sev_register_user_region(vm, region);

	sparsebit_for_each_set_range(protected_phy_pages, i, j) {
		const uint64_t size = (j - i + 1) * vm->page_size;
		const uint64_t offset = (i - lowest_page_in_region) * vm->page_size;

		sev_launch_update_data(vm, gpa_base + offset, size);
	}
}

bool is_kvm_sev_supported(void)
{
	struct sev_user_data_status sev_status;

	sev_ioctl(SEV_PLATFORM_STATUS, &sev_status);

	return sev_status.api_major > SEV_FW_REQ_VER_MAJOR ||
	       (sev_status.api_major == SEV_FW_REQ_VER_MAJOR &&
	        sev_status.api_minor >= SEV_FW_REQ_VER_MINOR);
}

static void sev_vm_launch(struct kvm_vm *vm, uint32_t policy)
{
	struct kvm_sev_launch_start launch_start = {
		.policy = policy,
	};
	struct userspace_mem_region *region;
	struct kvm_sev_guest_status status;
	int ctr;

	kvm_sev_ioctl(vm, KVM_SEV_LAUNCH_START, &launch_start);
	kvm_sev_ioctl(vm, KVM_SEV_GUEST_STATUS, &status);

	TEST_ASSERT(status.policy == policy, "Expected policy %d, got %d",
		    policy, status.policy);
	TEST_ASSERT(status.state == SEV_GSTATE_LUPDATE,
		    "Expected guest state %d, got %d",
		    SEV_GSTATE_LUPDATE, status.state);

	ucall_init(vm, 0);

	hash_for_each(vm->regions.slot_hash, ctr, region, slot_node)
		encrypt_region(vm, region);
}

static void sev_vm_launch_measure(struct kvm_vm *vm, uint8_t *measurement)
{
	struct kvm_sev_launch_measure launch_measure;
	struct kvm_sev_guest_status guest_status;

	launch_measure.len = 256;
	launch_measure.uaddr = (__u64)measurement;
	kvm_sev_ioctl(vm, KVM_SEV_LAUNCH_MEASURE, &launch_measure);

	kvm_sev_ioctl(vm, KVM_SEV_GUEST_STATUS, &guest_status);
	TEST_ASSERT(guest_status.state == SEV_GSTATE_LSECRET,
		    "Unexpected guest state: %d", guest_status.state);
}

static void sev_vm_launch_finish(struct kvm_vm *vm)
{
	struct kvm_sev_guest_status status;

	kvm_sev_ioctl(vm, KVM_SEV_GUEST_STATUS, &status);
	TEST_ASSERT(status.state == SEV_GSTATE_LUPDATE ||
		    status.state == SEV_GSTATE_LSECRET,
		    "Unexpected guest state: %d", status.state);

	kvm_sev_ioctl(vm, KVM_SEV_LAUNCH_FINISH, NULL);

	kvm_sev_ioctl(vm, KVM_SEV_GUEST_STATUS, &status);
	TEST_ASSERT(status.state == SEV_GSTATE_RUNNING,
		    "Unexpected guest state: %d", status.state);
}

static void sev_vm_measure(struct kvm_vm *vm)
{
	uint8_t measurement[512];
	int i;

	sev_vm_launch_measure(vm, measurement);

	/* TODO: Validate the measurement is as expected. */
	pr_debug("guest measurement: ");
	for (i = 0; i < 32; ++i)
		pr_debug("%02x", measurement[i]);
	pr_debug("\n");
}

void sev_vm_init(struct kvm_vm *vm)
{
	vm->arch.sev_fd = open_sev_dev_path_or_exit();

	kvm_sev_ioctl(vm, KVM_SEV_INIT, NULL);
}

struct kvm_vm *vm_sev_create_with_one_vcpu(uint32_t policy, void *guest_code,
					   struct kvm_vcpu **cpu)
{
	uint32_t mode = VM_MODE_PXXV48_4K | VM_SUBTYPE_SEV;
	struct kvm_vm *vm;
	struct kvm_vcpu *cpus[1];

	vm = __vm_create_with_vcpus(mode, 1, 0, guest_code, cpus);
	*cpu = cpus[0];

	sev_vm_launch(vm, policy);

	sev_vm_measure(vm);

	sev_vm_launch_finish(vm);

	pr_debug("SEV guest created, policy: 0x%x\n", policy);

	return vm;
}
