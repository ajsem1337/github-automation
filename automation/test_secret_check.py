"""Regression tests for the reusable scanner's privacy-preserving output."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/secret-check.yml"
SCRIPT = textwrap.dedent(WORKFLOW.read_text().split("        shell: python\n        run: |\n", 1)[1])


class SecretCheckTests(unittest.TestCase):
    def run_scanner(self, status, findings=None):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "gitleaks-redacted.json"
            if findings is not None:
                report.write_text(json.dumps(findings))
            output = io.StringIO()
            with patch.dict(os.environ, {"RUNNER_TEMP": directory}), \
                    patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], status)) as run, \
                    contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exit:
                exec(compile(SCRIPT, str(WORKFLOW), "exec"), {})
            arguments = run.call_args.args[0]
            self.assertIn("--redact=100", arguments)
            self.assertIn("--log-opts=--all", arguments)
            self.assertNotIn("capture_output", run.call_args.kwargs)
            self.assertEqual(run.call_args.kwargs["stderr"], subprocess.STDOUT)
            self.assertEqual(exit.exception.code, status)
            return output.getvalue()

    def test_clean_scan_passes(self):
        self.assertIn("No secrets detected", self.run_scanner(0))

    def test_findings_fail_without_printing_secret_or_snippet(self):
        output = self.run_scanner(1, [{
            "RuleID": "test-rule", "File": "example.txt", "StartLine": 7,
            "Commit": "fixture", "Secret": "never-print-this-value",
            "Match": "never-print-this-snippet",
        }])
        self.assertIn("1 potential secret(s)", output)
        self.assertIn("example.txt", output)
        self.assertNotIn("never-print", output)

    def test_scanner_failure_is_not_reported_as_clean(self):
        output = self.run_scanner(2)
        self.assertIn("could not complete", output)
        self.assertNotIn("No secrets detected", output)

    def test_missing_report_fails_closed(self):
        self.assertIn("could not complete", self.run_scanner(1))
