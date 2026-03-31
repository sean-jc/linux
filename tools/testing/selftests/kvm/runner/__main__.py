# SPDX-License-Identifier: GPL-2.0
# Copyright 2025 Google LLC
#
# Author: vipinsh@google.com (Vipin Sharma)

import argparse
import logging
import os
import sys

from test_runner import TestRunner
from selftest import SelftestStatus


def cli():
    parser = argparse.ArgumentParser(
        prog="KVM Selftests Runner",
        formatter_class=argparse.RawTextHelpFormatter,
        allow_abbrev=False
    )

    parser.add_argument("-t",
                        "--testcases",
                        nargs="*",
                        default=[],
                        help="Testcases to run. Provide the space separated testcases paths")

    parser.add_argument("-d",
                        "--dirs",
                        nargs="*",
                        default=[],
                        help="Run the testcases present in the given directory and all of its sub directories. Provide the space separated paths to add multiple directories.")

    return parser.parse_args()


def setup_logging():
    class TerminalColorFormatter(logging.Formatter):
        reset = "\033[0m"
        red_bold = "\033[31;1m"
        green = "\033[32m"
        yellow = "\033[33m"
        blue = "\033[34m"

        COLORS = {
            SelftestStatus.PASSED: green,
            SelftestStatus.NO_RUN: blue,
            SelftestStatus.SKIPPED: yellow,
            SelftestStatus.FAILED: red_bold
        }

        def __init__(self, fmt=None, datefmt=None):
            super().__init__(fmt, datefmt)

        def format(self, record):
            return (self.COLORS.get(record.levelno, "") +
                    super().format(record) + self.reset)

    logger = logging.getLogger("runner")
    logger.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch_formatter = TerminalColorFormatter(fmt="%(asctime)s | %(message)s",
                                          datefmt="%H:%M:%S")
    ch.setFormatter(ch_formatter)
    logger.addHandler(ch)


def fetch_testcases_in_dirs(dirs):
    testcases = []
    for dir in dirs:
        for root, child_dirs, files in os.walk(dir):
            for file in files:
                testcases.append(os.path.join(root, file))
    return testcases


def fetch_testcases(args):
    testcases = args.testcases
    testcases.extend(fetch_testcases_in_dirs(args.dirs))
    # Remove duplicates
    testcases = list(dict.fromkeys(testcases))
    return testcases


def main():
    args = cli()
    setup_logging()
    testcases = fetch_testcases(args)
    return TestRunner(testcases).start()


if __name__ == "__main__":
    PYTHON_VERSION = (3, 6)
    if sys.version_info < PYTHON_VERSION:
        print(f"Minimum required python version {PYTHON_VERSION}, found {sys.version}")
        sys.exit(1)

    sys.exit(main())
