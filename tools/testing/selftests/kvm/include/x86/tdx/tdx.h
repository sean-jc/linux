/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTEST_KVM_TDX_TDX_H
#define SELFTEST_KVM_TDX_TDX_H

#include <linux/types.h>

#define TDG_VP_VMCALL_VE_REQUEST_MMIO    48
#define TDVMCALL_MMIO_WRITE		  1

u64 __tdcall(u64 leaf, u64 r12, u64 r13, u64 r14, u64 r15);

static inline u64 tdx_mmio_write(u64 address, u32 size, u64 data_in)
{
	return __tdcall(TDG_VP_VMCALL_VE_REQUEST_MMIO, size,
			TDVMCALL_MMIO_WRITE, address, data_in);
}
#endif /* SELFTEST_KVM_TDX_TDX_H */
