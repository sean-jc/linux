/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTESTS_TDX_TDX_UTIL_H
#define SELFTESTS_TDX_TDX_UTIL_H

#include <stdbool.h>

#include "kvm_util.h"

static inline bool is_tdx_vm(struct kvm_vm *vm)
{
	return vm->type == KVM_X86_TDX_VM;
}

/*
 * TDX ioctls
 * Use underscores to avoid collisions with struct member names.
 */
#define __tdx_vm_ioctl(vm, cmd, _flags, arg)				\
({									\
	u64 r;								\
									\
	union {								\
		struct kvm_tdx_cmd c;					\
		unsigned long raw;					\
	} tdx_cmd = { .c = {						\
		.id = (cmd),						\
		.flags = (u32)(_flags),					\
		.data = (u64)(arg),					\
	} };								\
									\
	r = __vm_ioctl(vm, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd.raw);	\
	r ?: tdx_cmd.c.hw_error;					\
})

#define tdx_vm_ioctl(vm, cmd, flags, arg)				\
({									\
	u64 ret = __tdx_vm_ioctl(vm, cmd, flags, arg);			\
									\
	if (ret) {							\
		TEST_ASSERT(!ret,					\
			    "%s failed, rc: 0x%llx errno: %i (%s)",	\
			    #cmd, (unsigned long long)ret,		\
			    errno, strerror(errno));			\
	}								\
})

void tdx_init_vm(struct kvm_vm *vm, u64 attributes);

#endif /* SELFTESTS_TDX_TDX_UTIL_H */
