// SPDX-License-Identifier: GPL-2.0
/*
 * A test for GUEST_PRINTF
 *
 * Copyright 2022, Google, Inc. and/or its affiliates.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

/* GUEST_PRINTF()/GUEST_ASSERT_FMT() does not support float or double. */
#define TYPE_LIST					\
TYPE(test_type_i64,  I64,  "%ld",   int64_t)		\
TYPE(test_type_u64,  U64u, "%lu",   uint64_t)		\
TYPE(test_type_x64,  U64x, "0x%lx", uint64_t)		\
TYPE(test_type_X64,  U64X, "0x%lX", uint64_t)		\
TYPE(test_type_u32,  U32u, "%u",    uint32_t)		\
TYPE(test_type_x32,  U32x, "0x%x",  uint32_t)		\
TYPE(test_type_X32,  U32X, "0x%X",  uint32_t)		\
TYPE(test_type_int,  INT,  "%d",    int)		\
TYPE(test_type_char, CHAR, "%c",    char)		\
TYPE(test_type_str,  STR,  "'%s'",  const char *)	\
TYPE(test_type_ptr,  PTR,  "%p",    void *)

enum args_type {
#define TYPE(fn, ext, fmt_t, T) TYPE_##ext,
	TYPE_LIST
#undef TYPE
};

static void run_test(struct kvm_vcpu *vcpu, const char *expected_printf,
		     const char *expected_assert);

#define BUILD_TYPE_STRINGS_AND_HELPER(fn, ext, fmt_t, T)		     \
static void fn(struct kvm_vcpu *vcpu, T a, T b)				     \
{									     \
	char expected_printf[UCALL_BUFFER_LEN];				     \
	char expected_assert[UCALL_BUFFER_LEN];				     \
									     \
	snprintf(expected_printf, UCALL_BUFFER_LEN,\
		 "Got params a = " fmt_t " and b = " fmt_t, a, b); \
	snprintf(expected_assert, UCALL_BUFFER_LEN,				\
		 "Expected " fmt_t ", got " fmt_t " instead", a, b); \
	vcpu_args_set(vcpu, 3, a, b, TYPE_##ext);			     \
	run_test(vcpu, expected_printf, expected_assert);		     \
}

#define TYPE(fn, ext, fmt_t, T) \
		BUILD_TYPE_STRINGS_AND_HELPER(fn, ext, fmt_t, T)
	TYPE_LIST
#undef TYPE

static void guest_code(uint64_t a, uint64_t b, uint64_t type)
{
	switch (type) {
#define TYPE(fn, ext, fmt_t, T) case TYPE_##ext:			\
		GUEST_PRINTF("Got params a = " fmt_t " and b = " fmt_t, a, b);			\
		GUEST_ASSERT_FMT(a == b, "Expected " fmt_t ", got " fmt_t " instead", a, b);	\
		break;
	TYPE_LIST
#undef TYPE
	default:
		GUEST_SYNC(type);
	}

	GUEST_DONE();
}

/*
 * Unfortunately this gets a little messy because 'assert_msg' doesn't
 * just contains the matching string, it also contains additional assert
 * info.  Fortunately the part that matches should be at the very end of
 * 'assert_msg'.
 */
static void ucall_abort(const char *assert_msg, const char *expected_assert_msg)
{
	int len_str = strlen(assert_msg);
	int len_substr = strlen(expected_assert_msg);
	int offset = len_str - len_substr;

	TEST_ASSERT(len_substr <= len_str,
		    "Expected to find a substring, len_str: %d, len_substr: %d",
		    len_str, len_substr);

	TEST_ASSERT(strcmp(&assert_msg[offset], expected_assert_msg) == 0,
		    "Unexpected mismatch. Expected: '%s', got: '%s'",
		    expected_assert_msg, &assert_msg[offset]);
}

static void run_test(struct kvm_vcpu *vcpu, const char *expected_printf,
		     const char *expected_assert)
{
	struct kvm_run *run = vcpu->run;
	struct kvm_regs regs;
	struct ucall uc;

	/*
	 * The guest takes 3 parameters (T val1, T val2, TYPE) which are set
	 * in the parent call to allow run_tests() to be type-agnostic.
	 */

	vcpu_regs_get(vcpu, &regs);
	regs.rip = (uintptr_t)guest_code;
	vcpu_regs_set(vcpu, &regs);

	while (1) {
		vcpu_run(vcpu);

		TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
			    "Unexpected exit reason: %u (%s),\n",
			    run->exit_reason,
			    exit_reason_str(run->exit_reason));

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_SYNC:
			TEST_FAIL("Unknown 'args_type' = %lu", uc.args[1]);
			break;
		case UCALL_PRINTF:
			TEST_ASSERT(strcmp(uc.buffer, expected_printf) == 0,
				    "Unexpected mismatch. Expected: '%s', got: '%s'",
				    expected_printf, uc.buffer);
			break;
		case UCALL_ABORT:
			ucall_abort(uc.buffer, expected_assert);
			break;
		case UCALL_DONE:
			return;
		default:
			TEST_FAIL("Unknown ucall %lu", uc.cmd);
		}
	}
}

static void test_limits(void)
{
	const int buffer_len = UCALL_BUFFER_LEN + 10;
	char test_str[buffer_len];
	char test_res[buffer_len];
	int r;

	memset(test_str, 'a', buffer_len);
	test_str[buffer_len - 1] = 0;

	r = kvm_snprintf(test_res, UCALL_BUFFER_LEN, "%s", test_str);
	TEST_ASSERT(r == (buffer_len - 1),
		    "Unexpected kvm_snprintf() length.  Expected: %d, got: %d",
		    buffer_len - 1, r);

	r = strlen(test_res);
	TEST_ASSERT(r == (UCALL_BUFFER_LEN - 1),
		    "Unexpected strlen() length.  Expected: %d, got: %d",
		    UCALL_BUFFER_LEN - 1, r);
}

int main(int argc, char *argv[])
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	vm = vm_create_with_one_vcpu(&vcpu, NULL);

	test_type_i64(vcpu, -1, -1);
	test_type_i64(vcpu, -1,  1);
	test_type_i64(vcpu, 0x1234567890abcdef, 0x1234567890abcdef);
	test_type_i64(vcpu, 0x1234567890abcdef, 0x1234567890abcdee);

	test_type_u64(vcpu, 0x1234567890abcdef, 0x1234567890abcdef);
	test_type_u64(vcpu, 0x1234567890abcdef, 0x1234567890abcdee);
	test_type_x64(vcpu, 0x1234567890abcdef, 0x1234567890abcdef);
	test_type_x64(vcpu, 0x1234567890abcdef, 0x1234567890abcdee);
	test_type_X64(vcpu, 0x1234567890abcdef, 0x1234567890abcdef);
	test_type_X64(vcpu, 0x1234567890abcdef, 0x1234567890abcdee);

	test_type_u32(vcpu, 0x90abcdef, 0x90abcdef);
	test_type_u32(vcpu, 0x90abcdef, 0x90abcdee);
	test_type_x32(vcpu, 0x90abcdef, 0x90abcdef);
	test_type_x32(vcpu, 0x90abcdef, 0x90abcdee);
	test_type_X32(vcpu, 0x90abcdef, 0x90abcdef);
	test_type_X32(vcpu, 0x90abcdef, 0x90abcdee);

	test_type_int(vcpu, -1, -1);
	test_type_int(vcpu, -1,  1);
	test_type_int(vcpu,  1,  1);

	test_type_char(vcpu, 'a', 'a');
	test_type_char(vcpu, 'a', 'A');
	test_type_char(vcpu, 'a', 'b');

	test_type_str(vcpu, "foo", "foo");
	test_type_str(vcpu, "foo", "bar");

	test_type_ptr(vcpu, (void *)0x1234567890abcdef, (void *)0x1234567890abcdef);
	test_type_ptr(vcpu, (void *)0x1234567890abcdef, (void *)0x1234567890abcdee);

	kvm_vm_free(vm);

	test_limits();

	return 0;
}
