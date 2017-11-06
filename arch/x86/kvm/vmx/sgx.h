/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_SGX_H
#define __KVM_X86_SGX_H

#ifdef CONFIG_INTEL_SGX_VIRTUALIZATION
int handle_encls_ecreate(struct kvm_vcpu *vcpu);
int handle_encls_einit(struct kvm_vcpu *vcpu);
#endif

#endif /* __KVM_X86_SGX_H */

