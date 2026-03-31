# SPDX-License-Identifier: GPL-2.0
# Copyright 2025 Google LLC
#
# Author: vipinsh@google.com (Vipin Sharma)

import argparse
import logging
import os
import sys
import datetime
import pathlib

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

    parser.add_argument("-p",
                        "--path",
                        nargs='?',
                        default=".",
                        help="Finds the test executables in the given path. Default is the current directory.")

    parser.add_argument("--timeout",
                        default=120,
                        type=int,
                        help="Timeout, in seconds, before runner kills the running test. (Default: 120 seconds)")

    parser.add_argument("-o",
                        "--output",
                        nargs='?',
                        help="Dumps test runner output which includes each test execution result, their stdouts and stderrs hierarchically in the given directory.")

    parser.add_argument("--append-output-time",
                        action="store_true",
                        default=False,
                        help="Appends timestamp to the output directory.")

    return parser.parse_args()


def setup_logging(args):
    class TerminalColorFormatter(logging.Formatter):
        reset = "\033[0m"
        red_bold = "\033[31;1m"
        red = "\033[31;1m"
        green = "\033[32m"
        yellow = "\033[33m"
        blue = "\033[34m"

        COLORS = {
            SelftestStatus.PASSED: green,
            SelftestStatus.NO_RUN: blue,
            SelftestStatus.SKIPPED: yellow,
            SelftestStatus.FAILED: red_bold,
            SelftestStatus.TIMED_OUT: red
        }

        def __init__(self, fmt=None, datefmt=None):
            super().__init__(fmt, datefmt)

        def format(self, record):
            return (self.COLORS.get(record.levelno, "") +
                    super().format(record) + self.reset)

    logger = logging.getLogger("runner")
    logger.setLevel(logging.INFO)

    formatter_args = {
        "fmt": "%(asctime)s | %(message)s",
        "datefmt": "%H:%M:%S"
    }

    ch = logging.StreamHandler()
    ch_formatter = TerminalColorFormatter(**formatter_args)
    ch.setFormatter(ch_formatter)
    logger.addHandler(ch)

    if args.output != None:
        if (args.append_output_time):
            args.output += datetime.datetime.now().strftime(".%Y.%m.%d.%H.%M.%S")
        pathlib.Path(args.output).mkdir(parents=True, exist_ok=True)
        logging_file = os.path.join(args.output, "log")
        fh = logging.FileHandler(logging_file)
        fh_formatter = logging.Formatter(**formatter_args)
        fh.setFormatter(fh_formatter)
        logger.addHandler(fh)


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
    setup_logging(args)
    testcases = fetch_testcases(args)
    return TestRunner(testcases, args).start()


if __name__ == "__main__":
    PYTHON_VERSION = (3, 6)
    if sys.version_info < PYTHON_VERSION:
        print(f"Minimum required python version {PYTHON_VERSION}, found {sys.version}")
        sys.exit(1)

    sys.exit(main())
