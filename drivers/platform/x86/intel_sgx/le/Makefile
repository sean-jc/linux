# SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
# Copyright(c) 2016-17 Intel Corporation.
#
# Authors:
#
# Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

KASAN_SANITIZE := n
OBJECT_FILES_NON_STANDARD := y
KCOV_INSTRUMENT := n
KBUILD_CFLAGS := -Wall -Werror -static -nostdlib -nostartfiles -fno-builtin \
		 -I$(obj)/include
KBUILD_AFLAGS += -I$(obj)/include

subdir- := enclave

always := sgx_le_proxy
clean-files := sgx_le_proxy

#
# sgx_le_proxy
#

sgx_le_proxy-y += main.o entry.o sgx_le_piggy.o string.o
targets += $(sgx_le_proxy-y)
SGX_LE_PROXY_OBJS = $(addprefix $(obj)/,$(sgx_le_proxy-y))

$(obj)/sgx_le_piggy.o: $(obj)/enclave/sgx_le.bin $(obj)/enclave/sgx_le.ss
$(obj)/enclave/sgx_le.bin $(obj)/enclave/sgx_le.ss: FORCE
	$(Q)$(MAKE) -j1 $(build)=$(obj)/enclave $@

targets += sgx_le_proxy
$(obj)/sgx_le_proxy: $(SGX_LE_PROXY_OBJS)
	$(call if_changed,ld)
