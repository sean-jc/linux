# SPDX-License-Identifier: GPL-2.0
# Copyright 2025 Google LLC
#
# Author: vipinsh@google.com (Vipin Sharma)

import pathlib
import enum
import os
import subprocess
import contextlib

class SelftestStatus(enum.IntEnum):
    """
    Selftest Status. Integer values are just +1 to the logging.INFO level.
    """

    PASSED = 21
    NO_RUN = 22
    SKIPPED = 23
    FAILED = 24
    TIMED_OUT = 25

    def __str__(self):
        return str.__str__(self.name)

class Selftest:
    """
    Represents a single selftest.

    Extract the test execution command from test file and executes it.
    """

    def __init__(self, test_path, path, timeout, output_dir):
        test_command = pathlib.Path(test_path).read_text().strip()
        if not test_command:
            raise ValueError("Empty test command in " + test_path)

        test_command = os.path.join(path, test_command)
        self.exists = os.path.isfile(test_command.split(maxsplit=1)[0])
        self.test_path = test_path
        self.command = test_command
        self.timeout = timeout
        if output_dir is not None:
            output_dir = os.path.join(output_dir, test_path.lstrip("./"))
        self.output_dir = output_dir
        self.status = SelftestStatus.NO_RUN
        self.stdout = ""
        self.stderr = ""

    def _run(self, output=None, error=None):
        run_args = {
            "universal_newlines": True,
            "shell": True,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "timeout": self.timeout,
        }
        try:
            proc = subprocess.run(self.command, **run_args)
            out, err = proc.stdout, proc.stderr

            if proc.returncode == 0:
                self.status = SelftestStatus.PASSED
            elif proc.returncode == 4:
                self.status = SelftestStatus.SKIPPED
            else:
                self.status = SelftestStatus.FAILED
        except subprocess.TimeoutExpired as e:
            self.status = SelftestStatus.TIMED_OUT
            out, err = e.stdout, e.stderr

        self.stdout = out.decode("utf-8", "replace") if isinstance(out, bytes) else (out or "")
        if output is not None:
            output.write(self.stdout)

        self.stderr = err.decode("utf-8", "replace") if isinstance(err, bytes) else (err or "")
        if error is not None:
            error.write(self.stderr)

    def run(self):
        if not self.exists:
            self.stderr = "File doesn't exist."
            return

        if self.output_dir is not None:
            pathlib.Path(self.output_dir).mkdir(parents=True, exist_ok=True)

        output = None
        error = None
        with contextlib.ExitStack() as stack:
            if self.output_dir is not None:
                output_path = os.path.join(self.output_dir, "stdout")
                output = stack.enter_context(
                    open(output_path, encoding="utf-8", mode="w"))

                error_path = os.path.join(self.output_dir, "stderr")
                error = stack.enter_context(
                    open(error_path, encoding="utf-8", mode="w"))
            return self._run(output, error)
