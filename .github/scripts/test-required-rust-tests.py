"""Check gate selection with every Cargo subprocess replaced by a mock."""

import contextlib
import io
from pathlib import Path
import runpy
import sys
import unittest
from unittest import mock


class FakeCargo:
    def __init__(self, summary, returncode=0):
        self.stdout = io.StringIO(summary)
        self.returncode = returncode

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def wait(self):
        return self.returncode


class TargetSelectionTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name("run-required-rust-tests.py")
        self.main = runpy.run_path(str(path))["main"]

    def invoke(self, args, summary="test result: ok. 1 passed; 0 failed; 0 ignored;\n", returncode=0):
        child = FakeCargo(summary, returncode)
        with mock.patch.object(sys, "argv", ["gate", "selected_filter", "1", *args]), \
                mock.patch("subprocess.Popen", return_value=child) as spawn, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = self.main()
        return result, spawn

    def test_absent_target_retains_library_default(self):
        result, spawn = self.invoke([])
        self.assertEqual(result, 0)
        self.assertEqual(spawn.call_args.args[0], [
            "cargo", "test", "--locked", "--lib", "selected_filter",
            "--", "--nocapture", "--test-threads=1",
        ])

    def test_nonempty_target_selects_only_named_integration(self):
        result, spawn = self.invoke(["--test", "api_cli_statsquery", "--ignored"])
        self.assertEqual(result, 0)
        self.assertEqual(spawn.call_args.args[0], [
            "cargo", "test", "--locked", "--test", "api_cli_statsquery", "selected_filter",
            "--", "--nocapture", "--test-threads=1", "--ignored",
        ])

    def test_empty_target_fails_before_any_subprocess(self):
        error = io.StringIO()
        with mock.patch.object(sys, "argv", ["gate", "selected_filter", "1", "--test", ""]), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("must not spawn")) as spawn, \
                contextlib.redirect_stderr(error):
            with self.assertRaises(SystemExit) as raised:
                self.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--test NAME must not be empty", error.getvalue())
        spawn.assert_not_called()

    def test_zero_executed_tests_cannot_pass_integration_gate(self):
        with self.assertRaisesRegex(SystemExit, "passed=0"):
            self.invoke(["--test", "api_cli_statsquery"], "test result: ok. 0 passed; 0 failed; 0 ignored;\n")

    def test_subprocess_failure_is_preserved(self):
        result, _ = self.invoke(["--test", "api_cli_statsquery"], "", returncode=101)
        self.assertEqual(result, 101)


if __name__ == "__main__":
    unittest.main()
