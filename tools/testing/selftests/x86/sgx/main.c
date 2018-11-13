// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <elf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "encl_piggy.h"
#include "defines.h"
#include "../../../../../arch/x86/kernel/cpu/sgx/arch.h"
#include "../../../../../arch/x86/include/uapi/asm/sgx.h"

static const uint64_t MAGIC = 0x1122334455667788ULL;

struct vdso_symtab {
	Elf64_Sym *elf_symtab;
	const char *elf_symstrtab;
	Elf64_Word *elf_hashtab;
};

static void *vdso_get_base_addr(char *envp[])
{
	Elf64_auxv_t *auxv;
	int i;

	for (i = 0; envp[i]; i++);
	auxv = (Elf64_auxv_t *)&envp[i + 1];

	for (i = 0; auxv[i].a_type != AT_NULL; i++) {
		if (auxv[i].a_type == AT_SYSINFO_EHDR)
			return (void *)auxv[i].a_un.a_val;
	}

	return NULL;
}

static Elf64_Dyn *vdso_get_dyntab(void *addr)
{
	Elf64_Ehdr *ehdr = addr;
	Elf64_Phdr *phdrtab = addr + ehdr->e_phoff;
	int i;

	for (i = 0; i < ehdr->e_phnum; i++)
		if (phdrtab[i].p_type == PT_DYNAMIC)
			return addr + phdrtab[i].p_offset;

	return NULL;
}

static void *vdso_get_dyn(void *addr, Elf64_Dyn *dyntab, Elf64_Sxword tag)
{
	int i;

	for (i = 0; dyntab[i].d_tag != DT_NULL; i++)
		if (dyntab[i].d_tag == tag)
			return addr + dyntab[i].d_un.d_ptr;

	return NULL;
}

static bool vdso_get_symtab(void *addr, struct vdso_symtab *symtab)
{
	Elf64_Dyn *dyntab = vdso_get_dyntab(addr);

	symtab->elf_symtab = vdso_get_dyn(addr, dyntab, DT_SYMTAB);
	if (!symtab->elf_symtab)
		return false;

	symtab->elf_symstrtab = vdso_get_dyn(addr, dyntab, DT_STRTAB);
	if (!symtab->elf_symstrtab)
		return false;

	symtab->elf_hashtab = vdso_get_dyn(addr, dyntab, DT_HASH);
	if (!symtab->elf_hashtab)
		return false;

	return true;
}

static unsigned long elf_sym_hash(const char *name)
{
	unsigned long h = 0, high;

	while (*name) {
		h = (h << 4) + *name++;
		high = h & 0xf0000000;

		if (high)
			h ^= high >> 24;

		h &= ~high;
	}

	return h;
}

static Elf64_Sym *vdso_symtab_get(struct vdso_symtab *symtab, const char *name)
{
	Elf64_Word bucketnum = symtab->elf_hashtab[0];
	Elf64_Word *buckettab = &symtab->elf_hashtab[2];
	Elf64_Word *chaintab = &symtab->elf_hashtab[2 + bucketnum];
	Elf64_Sym *sym;
	Elf64_Word i;

	for (i = buckettab[elf_sym_hash(name) % bucketnum]; i != STN_UNDEF;
	     i = chaintab[i]) {
		sym = &symtab->elf_symtab[i];
		if (!strcmp(name, &symtab->elf_symstrtab[sym->st_name]))
			return sym;
	}

	return NULL;
}

static bool encl_create(int dev_fd, unsigned long bin_size,
			struct sgx_secs *secs)
{
	struct sgx_enclave_create ioc;
	void *base;
	int rc;

	memset(secs, 0, sizeof(*secs));
	secs->ssa_frame_size = 1;
	secs->attributes = SGX_ATTR_MODE64BIT;
	secs->xfrm = 3;

	for (secs->size = 4096; secs->size < bin_size; )
		secs->size <<= 1;

	base = mmap(NULL, secs->size, PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_SHARED, dev_fd, 0);
	if (base == MAP_FAILED) {
		perror("mmap");
		return false;
	}

	secs->base = (uint64_t)base;

	ioc.src = (unsigned long)secs;
	rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_CREATE, &ioc);
	if (rc) {
		fprintf(stderr, "ECREATE failed rc=%d.\n", rc);
		munmap(base, secs->size);
		return false;
	}

	return true;
}

static bool encl_add_page(int dev_fd, unsigned long addr, void *data,
			  uint64_t flags)
{
	struct sgx_enclave_add_page ioc;
	struct sgx_secinfo secinfo;
	int rc;

	memset(&secinfo, 0, sizeof(secinfo));
	secinfo.flags = flags;

	ioc.secinfo = (unsigned long)&secinfo;
	ioc.mrmask = 0xFFFF;
	ioc.addr = addr;
	ioc.src = (uint64_t)data;

	rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_ADD_PAGE, &ioc);
	if (rc) {
		fprintf(stderr, "EADD failed rc=%d.\n", rc);
		return false;
	}

	return true;
}

static bool encl_load(struct sgx_secs *secs, unsigned long bin_size)
{
	struct sgx_enclave_init ioc;
	uint64_t offset;
	uint64_t flags;
	int dev_fd;
	int rc;

	dev_fd = open("/dev/sgx", O_RDWR);
	if (dev_fd < 0) {
		fprintf(stderr, "Unable to open /dev/sgx\n");
		return false;
	}

	if (!encl_create(dev_fd, bin_size, secs))
		goto out_dev_fd;

	for (offset = 0; offset < bin_size; offset += 0x1000) {
		if (!offset)
			flags = SGX_SECINFO_TCS;
		else
			flags = SGX_SECINFO_REG | SGX_SECINFO_R |
				SGX_SECINFO_W | SGX_SECINFO_X;

		if (!encl_add_page(dev_fd, secs->base + offset,
				   encl_bin + offset, flags))
			goto out_map;
	}

	ioc.addr = secs->base;
	ioc.sigstruct = (uint64_t)&encl_ss;
	rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_INIT, &ioc);
	if (rc) {
		printf("EINIT failed rc=%d\n", rc);
		goto out_map;
	}

	close(dev_fd);
	return true;
out_map:
	munmap((void *)secs->base, secs->size);
out_dev_fd:
	close(dev_fd);
	return false;
}

void sgx_call(void *rdi, void *rsi, void *tcs,
	      struct sgx_enclave_exception *exception,
	      void *eenter);

int main(int argc, char *argv[], char *envp[])
{
	unsigned long bin_size = encl_bin_end - encl_bin;
	unsigned long ss_size = encl_ss_end - encl_ss;
	struct sgx_enclave_exception exception;
	Elf64_Sym *eenter_sym;
	struct vdso_symtab symtab;
	struct sgx_secs secs;
	uint64_t result = 0;
	void *eenter;
	void *addr;

	memset(&exception, 0, sizeof(exception));

	addr = vdso_get_base_addr(envp);
	if (!addr)
		exit(1);

	if (!vdso_get_symtab(addr, &symtab))
		exit(1);

	eenter_sym = vdso_symtab_get(&symtab, "__vdso_sgx_enter_enclave");
	if (!eenter_sym)
		exit(1);
	eenter = addr + eenter_sym->st_value;

	printf("Binary size %lu (0x%lx), SIGSTRUCT size %lu\n", bin_size,
	       bin_size, ss_size);
	if (ss_size != sizeof(struct sgx_sigstruct)) {
		fprintf(stderr, "The size of SIGSTRUCT should be %lu\n",
			sizeof(struct sgx_sigstruct));
		exit(1);
	}

	printf("Loading the enclave.\n");
	if (!encl_load(&secs, bin_size))
		exit(1);

	printf("Input: 0x%lx\n", MAGIC);
	sgx_call((void *)&MAGIC, &result, (void *)secs.base, &exception,
		 eenter);
	if (result != MAGIC) {
		fprintf(stderr, "0x%lx != 0x%lx\n", result, MAGIC);
		exit(1);
	}

	printf("Output: 0x%lx\n", result);
	exit(0);
}
