KVM Selftest Runner
===================

Execute KVM selftests with high configurability. The runner supports parallel
execution, hierarchical output storage, console output control, and execution
status reporting.

Compatibility with KVM Selftests
===============================

The runner acts as a non-intrusive wrapper around the existing KVM selftests.
It does not modify the underlying test binaries or the way they are built.
You can still run KVM selftests using traditional methods without any conflict:

- Execute binaries directly: ``./dirty_log_perf_test -v 4``
- Use the standard kselftest framework: ``make -C tools/testing/selftests TARGETS=kvm run_tests``

Comparison with kselftest framework
===================================

While the standard ``kselftest`` framework provides basic execution and reporting,
this runner is designed for more advanced testing scenarios and offers several
advantages:

- **Flexible Test Selection**: Unlike some ``kselftest`` options that may use a
  fixed ``suite:test`` syntax for selection, this runner leverages the
  filesystem. You can group tests into directories (acting as suites) or
  provide a list of specific test files, offering a more intuitive way to
  organize and execute subsets of tests.
- **Parallel Execution**: Run tests concurrently using the ``-j`` flag to
  significantly reduce total execution time.
- **Granular Output Control**: Control exactly what gets printed to the console
  for passed, failed, skipped, or timed-out tests.
- **Hierarchical Logging**: Automatically save the stdout and stderr of every
  test into a structured directory tree, making it easy to debug failures in
  large test runs.
- **Out-of-Tree Support**: Easily run test binaries located in a different
  directory using the ``-p`` flag.

Generate Default Tests
======================

Generate the default test case files using the provided make target::

  # make testcases

Create a ``$(INSTALL_PATH)/$(DEFAULT_TESTCASES)`` directory and a sub-directory
for each KVM selftest, and populate each selftest sub-directory with a
``default.test`` file, where ``default.test`` contains the unqualified
executable path.

For example, the ``dirty_log_perf_test`` entry looks like::

  # cat $(DEFAULT_TESTCASES)/dirty_log_perf_test/default.test
  dirty_log_perf_test

Note, the ``testcases`` target is dependent on the ``install`` target, i.e.
installing testcases will also run ``install``.

Testcase Syntax
===============

Testcase files can provide extra arguments to the test::

  # cat tests/dirty_log_perf_test/2slot_5vcpu_10iter.test
  dirty_log_perf_test -x 2 -v 5 -i 10

In this case, the runner executes ``dirty_log_perf_test`` with the specified
options.

Examples
========

Display all options::

  # python3 runner -h

Run all default tests::

  # python3 runner -d $(DEFAULT_TESTCASES)

Run tests in parallel::

  # python3 runner -d $(DEFAULT_TESTCASES) -j 40

Print only passed test status and failed test stderr::

  # python3 runner -d $(DEFAULT_TESTCASES) --print-passed status \
  --print-failed stderr

Run test binaries from a different directory (e.g., out-of-tree builds)::

  # python3 runner -d $(DEFAULT_TESTCASES) -p /path/to/binaries

Save all test outputs (stdout, stderr, status) to a directory::

  # python3 runner -d $(DEFAULT_TESTCASES) -o test_outputs

Run specific testcase files::

  # python3 runner -t tests/dirty_log_perf_test/2slot_5vcpu_10iter.test
