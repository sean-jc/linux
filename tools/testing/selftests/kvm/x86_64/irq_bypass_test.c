// SPDX-License-Identifier: GPL-2.0-only
#include "apic.h"
#include "processor.h"
#include "test_util.h"
#include "kvm_util.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <syscall.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <time.h>

#include <sys/eventfd.h>

static int __eventfd;
static cpu_set_t possible_mask;
static int min_cpu, max_cpu;
static bool done;
static int irq_received = -1;

static void guest_irq_handler(struct ex_regs *regs)
{
	WRITE_ONCE(irq_received, irq_received + 1);
	x2apic_write_reg(APIC_EOI, 0x00);
}

static void guest_code(void)
{
	x2apic_enable();

	GUEST_ASSERT(READ_ONCE(irq_received) == -1);
	WRITE_ONCE(irq_received, 0);

	asm volatile("sti;hlt");

	GUEST_ASSERT(READ_ONCE(irq_received));

	for (;;) {
		udelay(10);

		asm volatile("cli");
		if (READ_ONCE(irq_received) < 10000)
			asm volatile("sti;hlt");
		else
			asm volatile("sti");

		GUEST_SYNC(0);
	}
}

static void *rerouting_worker(void *__vm)
{
	struct kvm_irq_routing *gsi_routing = kvm_gsi_routing_create();
	struct kvm_vm *vm = __vm;
	uint64_t val = POLL_IN;
	int i, r;

	do {
		sync_global_from_guest(vm, irq_received);
	} while (READ_ONCE(irq_received) != 0);

	gsi_routing->nr = 1;

	for (i = 0; i < 10000; i++) {
		gsi_routing->entries[0].gsi = 6;
		gsi_routing->entries[0].type = KVM_IRQ_ROUTING_MSI;
		gsi_routing->entries[0].flags = 0;
		gsi_routing->entries[0].u.msi.address_lo = 0;
		gsi_routing->entries[0].u.msi.address_hi = 0;
		gsi_routing->entries[0].u.msi.data = 0x80;
		vm_ioctl(vm, KVM_SET_GSI_ROUTING, gsi_routing);

		r = write(__eventfd, &val, sizeof(uint64_t));
		TEST_ASSERT(r == sizeof(uint64_t), __KVM_SYSCALL_ERROR("write()", r));

		do {
			sync_global_from_guest(vm, irq_received);
		} while (READ_ONCE(irq_received) == i);

		gsi_routing->entries[0].gsi = 6;
		gsi_routing->entries[0].type = KVM_IRQ_ROUTING_IRQCHIP;
		gsi_routing->entries[0].flags = 0;
		gsi_routing->entries[0].u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC;
		gsi_routing->entries[0].u.irqchip.pin = 6;
		vm_ioctl(vm, KVM_SET_GSI_ROUTING, gsi_routing);
	}

	WRITE_ONCE(done, true);

	return NULL;
}
static int next_cpu(int cpu)
{
	/*
	 * Advance to the next CPU, skipping those that weren't in the original
	 * affinity set.  Sadly, there is no CPU_SET_FOR_EACH, and cpu_set_t's
	 * data storage is considered as opaque.  Note, if this task is pinned
	 * to a small set of discontigous CPUs, e.g. 2 and 1023, this loop will
	 * burn a lot cycles and the test will take longer than normal to
	 * complete.
	 */
	do {
		cpu++;
		if (cpu > max_cpu) {
			cpu = min_cpu;
			TEST_ASSERT(CPU_ISSET(cpu, &possible_mask),
				    "Min CPU = %d must always be usable", cpu);
			break;
		}
	} while (!CPU_ISSET(cpu, &possible_mask));

	return cpu;
}

static void *migration_worker(void *__guest_tid)
{
	pid_t guest_tid = (pid_t)(unsigned long)__guest_tid;
	cpu_set_t allowed_mask;
	int r, i, cpu;

	CPU_ZERO(&allowed_mask);

	for (i = 0, cpu = min_cpu; !READ_ONCE(done); i++, cpu = next_cpu(cpu)) {
		CPU_SET(cpu, &allowed_mask);

		r = sched_setaffinity(guest_tid, sizeof(allowed_mask), &allowed_mask);
		TEST_ASSERT(!r, "sched_setaffinity failed, errno = %d (%s)",
			    errno, strerror(errno));

		CPU_CLR(cpu, &allowed_mask);

		usleep((i % 10) + 1);
	}
	return NULL;
}

static void calc_min_max_cpu(void)
{
	int i, cnt, nproc;

	TEST_REQUIRE(CPU_COUNT(&possible_mask) >= 2);

	/*
	 * CPU_SET doesn't provide a FOR_EACH helper, get the min/max CPU that
	 * this task is affined to in order to reduce the time spent querying
	 * unusable CPUs, e.g. if this task is pinned to a small percentage of
	 * total CPUs.
	 */
	nproc = get_nprocs_conf();
	min_cpu = -1;
	max_cpu = -1;
	cnt = 0;

	for (i = 0; i < nproc; i++) {
		if (!CPU_ISSET(i, &possible_mask))
			continue;
		if (min_cpu == -1)
			min_cpu = i;
		max_cpu = i;
		cnt++;
	}

	__TEST_REQUIRE(cnt >= 2, "Only one usable CPU, task migration not possible");
}

int main(int argc, char *argv[])
{
	pthread_t migration_thread, rerouting_thread;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int r;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vm_install_exception_handler(vm, 0x80, guest_irq_handler);

	__eventfd = eventfd(0, 0);
	TEST_ASSERT(__eventfd != -1, __KVM_SYSCALL_ERROR("eventfd()", __eventfd));

	struct kvm_irqfd irqfd = {
		.fd  = __eventfd,
		.gsi = 6,
	};
	vm_ioctl(vm, KVM_IRQFD, &irqfd);

	pthread_create(&rerouting_thread, NULL, rerouting_worker, (void *)vm);

	r = sched_getaffinity(0, sizeof(possible_mask), &possible_mask);
	TEST_ASSERT(!r, "sched_getaffinity failed, errno = %d (%s)", errno,
		    strerror(errno));

	calc_min_max_cpu();

	pthread_create(&migration_thread, NULL, migration_worker,
		       (void *)(unsigned long)syscall(SYS_gettid));

	do {
		vcpu_run(vcpu);
		TEST_ASSERT_EQ(get_ucall(vcpu, NULL), UCALL_SYNC);
	} while (!READ_ONCE(done));

	kvm_vm_free(vm);
	close(__eventfd);

	return 0;
}
