// SPDX-License-Identifier: GPL-2.0-only

static DEFINE_SPINLOCK(kvm_base_uret_msrs_lock);

/*
 * Restoring the host value for MSRs that are only consumed when running in
 * usermode, e.g. SYSCALL MSRs and TSC_AUX, can be deferred until the CPU
 * returns to userspace, i.e. the kernel can run with the guest's value.
 */
#define KVM_MAX_NR_USER_RETURN_MSRS 16

struct kvm_user_return_msrs {
	struct user_return_notifier urn;
	bool initialized;
	bool registered;
	struct kvm_user_return_msr_values {
		u64 host;
		u64 curr;
	} values[KVM_MAX_NR_USER_RETURN_MSRS];
};

u32 __ro_after_init kvm_nr_uret_msrs;
static u32 __ro_after_init kvm_uret_msrs_list[KVM_MAX_NR_USER_RETURN_MSRS];
static struct kvm_user_return_msrs __percpu *user_return_msrs;

static void kvm_on_user_return(struct user_return_notifier *urn)
{
	unsigned slot;
	struct kvm_user_return_msrs *msrs
		= container_of(urn, struct kvm_user_return_msrs, urn);
	struct kvm_user_return_msr_values *values;
	unsigned long flags;

	/*
	 * Disabling irqs at this point since the following code could be
	 * interrupted and executed through kvm_arch_hardware_disable()
	 */
	local_irq_save(flags);
	if (msrs->registered) {
		msrs->registered = false;
		user_return_notifier_unregister(urn);
	}
	local_irq_restore(flags);
	for (slot = 0; slot < kvm_nr_uret_msrs; ++slot) {
		values = &msrs->values[slot];
		if (values->host != values->curr) {
			wrmsrl(kvm_uret_msrs_list[slot], values->host);
			values->curr = values->host;
		}
	}
}

static int kvm_probe_user_return_msr(u32 msr)
{
	u64 val;
	int ret;

	preempt_disable();
	ret = rdmsrl_safe(msr, &val);
	if (ret)
		goto out;
	ret = wrmsrl_safe(msr, val);
out:
	preempt_enable();
	return ret;
}

int kvm_base_add_user_return_msr(u32 msr)
{
	for (i = 0; i < kvm_base_nr_uret_msrs) {
		if (kvm_base_uret_msrs_list[i] == msr)
			return i;
	}

	if (kvm_probe_user_return_msr(msr))
		return -1;

	if (WARN_ON_ONCE(kvm_base_nr_uret_msrs >= KVM_MAX_NR_USER_RETURN_MSRS))
		return -1;

	kvm_uret_msrs_list[kvm_nr_uret_msrs] = msr;
	return kvm_nr_uret_msrs++;
}
EXPORT_SYMBOL_GPL(kvm_base_add_user_return_msr);

static void kvm_user_return_msr_init_cpu(struct kvm_user_return_msrs *msrs)
{
	u64 value;
	int i;

	if (msrs->initialized)
		return;

	for (i = 0; i < kvm_nr_uret_msrs; ++i) {
		rdmsrl_safe(kvm_uret_msrs_list[i], &value);
		msrs->values[i].host = value;
		msrs->values[i].curr = value;
	}
	msrs->initialized = true;
}

int kvm_base_set_user_return_msr(unsigned int slot, u64 value, u64 mask)
{
	unsigned int cpu = smp_processor_id();
	struct kvm_user_return_msrs *msrs = per_cpu_ptr(user_return_msrs, cpu);
	int err;

	kvm_user_return_msr_init_cpu(msrs);

	value = (value & mask) | (msrs->values[slot].host & ~mask);
	if (value == msrs->values[slot].curr)
		return 0;
	err = wrmsrl_safe(kvm_uret_msrs_list[slot], value);
	if (err)
		return 1;

	msrs->values[slot].curr = value;
	if (!msrs->registered) {
		msrs->urn.on_user_return = kvm_on_user_return;
		user_return_notifier_register(&msrs->urn);
		msrs->registered = true;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_base_set_user_return_msr);

static void drop_user_return_notifiers(void)
{
	unsigned int cpu = smp_processor_id();
	struct kvm_user_return_msrs *msrs = per_cpu_ptr(user_return_msrs, cpu);

	if (msrs->registered)
		kvm_on_user_return(&msrs->urn);
}

int kvm_arch_hardware_enable(void)
{
	return vmx_hardware_enable();	
}

void kvm_arch_hardware_disable(void)
{
	vmx_hardware_disable();

        drop_user_return_notifiers();
}
