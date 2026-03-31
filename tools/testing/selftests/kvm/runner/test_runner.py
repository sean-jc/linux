# SPDX-License-Identifier: GPL-2.0
# Copyright 2025 Google LLC
#
# Author: vipinsh@google.com (Vipin Sharma)

import logging
import concurrent.futures

from selftest import Selftest
from selftest import SelftestStatus

logger = logging.getLogger("runner")


class TestRunner:
    def __init__(self, testcases, args):
        self.tests = []
        self.output_dir = args.output
        self.jobs = args.jobs

        for testcase in testcases:
            self.tests.append(Selftest(testcase, args.path, args.timeout,
                                       args.output))

    def _run_test(self, test):
        test.run()
        return test

    def _log_result(self, test_result):
        logger.info("*** stdout ***\n" + test_result.stdout)
        logger.info("*** stderr ***\n" + test_result.stderr)
        logger.log(test_result.status,
                   f"[{test_result.status.name}] {test_result.test_path}")

    def start(self):
        ret = 0

        with concurrent.futures.ProcessPoolExecutor(max_workers=self.jobs) as executor:
            all_futures = []
            for test in self.tests:
                future = executor.submit(self._run_test, test)
                all_futures.append(future)

            for future in concurrent.futures.as_completed(all_futures):
                test_result = future.result()
                self._log_result(test_result)
                if (test_result.status not in [SelftestStatus.PASSED,
                                               SelftestStatus.NO_RUN,
                                               SelftestStatus.SKIPPED]):
                    ret = 1
        return ret
