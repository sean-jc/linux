# SPDX-License-Identifier: GPL-2.0
# Copyright 2025 Google LLC
#
# Author: vipinsh@google.com (Vipin Sharma)

import logging
from selftest import Selftest
from selftest import SelftestStatus

logger = logging.getLogger("runner")


class TestRunner:
    def __init__(self, testcases, args):
        self.tests = []
        self.output_dir = args.output

        for testcase in testcases:
            self.tests.append(Selftest(testcase, args.path, args.timeout,
                                       args.output))

    def _log_result(self, test_result):
        logger.info("*** stdout ***\n" + test_result.stdout)
        logger.info("*** stderr ***\n" + test_result.stderr)
        logger.log(test_result.status,
                   f"[{test_result.status.name}] {test_result.test_path}")

    def start(self):
        ret = 0

        for test in self.tests:
            test.run()
            self._log_result(test)

            if (test.status not in [SelftestStatus.PASSED,
                                    SelftestStatus.NO_RUN,
                                    SelftestStatus.SKIPPED]):
                ret = 1
        return ret
