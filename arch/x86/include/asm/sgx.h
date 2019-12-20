/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SGX_H
#define _ASM_X86_SGX_H

#include <linux/kvm_types.h>
#include <linux/types.h>

int sgx_set_attribute(u64 *allowed_attributes, unsigned int attribute_fd);

#ifdef CONFIG_INTEL_SGX_VIRTUALIZATION
struct sgx_pageinfo;

int sgx_virt_ecreate(struct sgx_pageinfo *pageinfo, void __user *secs,
		     int *trapnr);
int sgx_virt_einit(void __user *sigstruct, void __user *token,
		   void __user *secs, u64 *lepubkeyhash, int *trapnr);

typedef unsigned long (gfn_to_hva_fn_t)(struct kvm *kvm, gfn_t gfn);

void *sgx_virt_enable_reclaim(int epc_fd, struct kvm *kvm,
			      gfn_to_hva_fn_t *fn);
void sgx_virt_disable_reclaim(void *epc);
bool sgx_virt_host_tracked(void *epc, unsigned long hva);
bool sgx_virt_host_locked(void *epc, unsigned long hva);

#endif

#endif /* _ASM_X86_SGX_H */
