#ifndef __KVM_BASE_H
#define __KVM_BASE_H

static inline int kvm_base_init(void)
{
#ifndef CONFIG_HAVE_KVM_SEPARATE_BASE
        return __kvm_base_init();
#else
        return 0;
#endif
}

static inline void kvm_base_exit(void)
{
#ifndef CONFIG_HAVE_KVM_SEPARATE_BASE
        __kvm_base_exit();
#endif
}

int kvm_hardware_enable_all(void);
int kvm_hardware_disable_all(void);

int kvm_arch_hardware_enable(void);
void kvm_arch_hardware_disable(void);

#endif /* __KVM_BASE_H */
