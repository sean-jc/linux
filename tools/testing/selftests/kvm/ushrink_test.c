// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <sys/sysinfo.h>

#include <linux/ushrink.h>

#include "apic.h"
#include "kvm_util.h"
#include "processor.h"

#define USHRINK_GSI		0x20
#define USHRINK_IRQ_VECTOR	0x80

static int irqs_received;
static struct ushrink_notification notification;

static void guest_irq_handler(struct ex_regs *regs)
{
	WRITE_ONCE(irqs_received, irqs_received + 1);

	x2apic_write_reg(APIC_EOI, 0);
}

static void guest_code(struct ex_regs *regs)
{
	cli();
	x2apic_enable();
	sti_nop();

	while (READ_ONCE(irqs_received) < 10)
		;

	GUEST_ASSERT(notification.priority == 0xbeef);
	GUEST_DONE();
}

int main(int argc, char *argv[])
{
	struct kvm_irq_routing *routing;
	struct ushrink_register u;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int fd;

	fd = open_path_or_exit("/dev/ushrink", O_RDONLY);

	/* Create "full" VMs, as KVM_IRQFD requires an in-kernel IRQ chip. */
	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vm_install_exception_handler(vm, USHRINK_IRQ_VECTOR, guest_irq_handler);

	u.eventfd = kvm_new_eventfd();
	u.notification = (u64)addr_gva2hva(vm, (vm_vaddr_t)&notification);
	kvm_ioctl(fd, USHRINK_REGISTER, &u);

	routing = kvm_gsi_routing_create();
	routing->nr = 1;
	routing->entries[0].gsi = USHRINK_GSI;
	routing->entries[0].type = KVM_IRQ_ROUTING_MSI;
	routing->entries[0].flags = 0;
	routing->entries[0].u.msi.address_lo = (vcpu->id << 12);
	routing->entries[0].u.msi.address_hi = 0;
	routing->entries[0].u.msi.data = USHRINK_IRQ_VECTOR;
	vm_ioctl(vcpu->vm, KVM_SET_GSI_ROUTING, routing);

	kvm_irqfd(vm, USHRINK_GSI, u.eventfd, 0);

	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, NULL), UCALL_DONE);

	kvm_irqfd(vm, USHRINK_GSI, u.eventfd, KVM_IRQFD_FLAG_DEASSIGN);
	kvm_ioctl(fd, USHRINK_UNREGISTER, &u);
	close(u.eventfd);
	free(routing);
}
