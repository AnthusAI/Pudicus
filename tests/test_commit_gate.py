"""Commit-gate regressions using synthetic data and disposable Git repositories."""

import argparse
import json
import os
import random
import shlex
import shutil
import string
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pudicus import cli
from pudicus.core import CheckerResult, run_command_checker, run_tactus_checker


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GITLEAKS = shutil.which("gitleaks")


def synthetic_key():
    rng = random.Random(2718)
    return "sk-" + "proj-" + "".join(
        rng.choice(string.ascii_letters + string.digits) for _ in range(48)
    )


class RepositoryFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.secret = self.root / "receipt-secret"
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("GIT_", "GITLEAKS_", "PUDICUS_"))
        }
        self.env.update({
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "PUDICUS_SECRET_PATH": str(self.secret),
            "PYTHONPATH": str(PROJECT_ROOT),
        })
        self.git("init", check=True)
        self.git("config", "user.name", "Synthetic Test", check=True)
        self.git("config", "user.email", "test@example.com", check=True)
        self.git("config", "commit.gpgsign", "false", check=True)
        # Only the disposable repository gets history. No real checkout is changed.
        self.git("commit", "--allow-empty", "-m", "test: baseline", check=True)
        self.baseline = self.git("rev-parse", "HEAD", check=True).stdout.strip()
        self.msg = self.root / "message.txt"
        self.msg.write_text("test: synthetic gate\n")

    def git(self, *args, check=False):
        proc = subprocess.run(
            ["git", *args], cwd=self.repo, env=self.env,
            text=True, capture_output=True, stdin=subprocess.DEVNULL,
        )
        if check:
            self.assertEqual(proc.returncode, 0, "Disposable Git setup failed")
        return proc

    def pudicus(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "pudicus.cli", *args],
            cwd=self.repo, env=self.env, text=True, capture_output=True,
            stdin=subprocess.DEVNULL,
        )

    def stage(self, content):
        (self.repo / "fixture.txt").write_text(content)
        self.git("add", "fixture.txt", check=True)

    def policy(self, command, **extra):
        checker = {"name": "synthetic-scanner", "type": "command", "command": command}
        checker.update(extra)
        # JSON is valid YAML, and avoids shell/YAML quoting ambiguity.
        (self.repo / ".pudicus.yml").write_text(
            json.dumps({"version": 1, "checkers": [checker]})
        )

    def script(self, body):
        path = self.root / "synthetic_checker.py"
        path.write_text(body)
        return shlex.join([sys.executable, str(path)])

    def assert_not_committed(self):
        current = self.git("rev-parse", "HEAD", check=True).stdout.strip()
        self.assertEqual(current, self.baseline, "Rejected change reached Git history")


@unittest.skipUnless(GITLEAKS, "Gitleaks must be installed for actual scanner tests")
class GitleaksCommitGateTests(RepositoryFixture):
    def setUp(self):
        super().setUp()
        proc = self.pudicus("install")
        self.assertEqual(proc.returncode, 0, "Pudicus hook installation failed")

    def test_clean_commit_passes_and_has_receipt(self):
        self.stage("A harmless staged fixture.\n")
        proc = self.git("commit", "-m", "test: clean fixture")
        self.assertEqual(proc.returncode, 0, "Clean fixture was blocked")
        message = self.git("log", "-1", "--format=%B", check=True).stdout
        self.assertIn("Inspection-result: clean", message)
        self.assertIn("Inspection-sig: hmac-sha256:", message)

    def test_sensitive_commit_is_blocked_before_head_changes(self):
        value = synthetic_key()
        self.stage('api_key = "' + value + '"\n')
        proc = self.git("commit", "-m", "test: rejected fixture")
        self.assertNotEqual(proc.returncode, 0, "Synthetic sensitive fixture was accepted")
        self.assertIn("pudicus-openai-key", proc.stderr)
        self.assertTrue(value not in proc.stdout + proc.stderr, "Sensitive fixture leaked to output")
        self.assert_not_committed()

    def test_sensitive_index_still_blocks_with_clean_working_file(self):
        self.stage('api_key = "' + synthetic_key() + '"\n')
        (self.repo / "fixture.txt").write_text("Clean but unstaged replacement.\n")
        proc = self.git("commit", "-m", "test: partial staging rejected")
        self.assertNotEqual(proc.returncode, 0, "Scanner ignored sensitive staged content")
        self.assert_not_committed()

    def test_clean_index_passes_with_sensitive_unstaged_file(self):
        self.stage("Clean staged content.\n")
        (self.repo / "fixture.txt").write_text('api_key = "' + synthetic_key() + '"\n')
        proc = self.git("commit", "-m", "test: partial staging clean")
        self.assertEqual(proc.returncode, 0, "Scanner used unstaged content")
        committed = self.git("show", "HEAD:fixture.txt", check=True).stdout
        self.assertEqual(committed, "Clean staged content.\n")

    def test_scan_only_needs_no_secret_and_writes_no_receipt(self):
        self.stage("Clean staged content.\n")
        self.secret.unlink()
        original_message = self.msg.read_bytes()
        proc = self.pudicus("check")
        self.assertEqual(proc.returncode, 0, "Scan-only unexpectedly needed a signing secret")
        self.assertFalse(self.secret.exists())
        self.assertEqual(self.msg.read_bytes(), original_message)
        self.assert_not_committed()

    def test_scan_only_blocks_sensitive_index(self):
        self.stage('api_key = "' + synthetic_key() + '"\n')
        proc = self.pudicus("check")
        self.assertNotEqual(proc.returncode, 0, "Scan-only accepted sensitive staged content")
        self.assert_not_committed()


class FailClosedGateTests(RepositoryFixture):
    def setUp(self):
        super().setUp()
        self.secret.write_text("synthetic-receipt-secret")
        self.secret.chmod(0o600)
        self.stage("Harmless staged data.\n")

    def assert_blocked(self):
        for args in (("check",), ("hook", str(self.msg))):
            with self.subTest(command=args[0]):
                proc = self.pudicus(*args)
                self.assertNotEqual(proc.returncode, 0, "Invalid inspection was allowed")
                self.assertNotIn("Inspection-sig:", self.msg.read_text())
        self.assert_not_committed()

    def test_missing_empty_and_malformed_policy_block(self):
        config = self.repo / ".pudicus.yml"
        for content in (None, "", "version: 1\ncheckers: []\n", "checkers: [", "[]"):
            with self.subTest(policy=content):
                if content is None:
                    if config.exists():
                        config.unlink()
                else:
                    config.write_text(content)
                self.assert_blocked()

    def test_unrecognized_checker_or_success_code_blocks(self):
        cases = (
            {"type": "unrecognized", "command": "true"},
            {"type": "command", "command": "true", "success_codes": [0, 1]},
            {"type": "command", "command": "true", "finding_codes": [0, 1]},
            {"type": "command", "command": ""},
        )
        for checker in cases:
            with self.subTest(checker=checker):
                (self.repo / ".pudicus.yml").write_text(json.dumps({"checkers": [checker]}))
                self.assert_blocked()

    def test_missing_scanner_blocks(self):
        self.policy(str(self.root / "nonexistent-scanner"))
        self.assert_blocked()

    def test_explicit_disjoint_success_code_is_preserved(self):
        command = self.script("import sys\nsys.exit(3)\n")
        self.policy(command, success_codes=[0, 3], finding_codes=[1])
        for args in (("check",), ("hook", str(self.msg))):
            with self.subTest(command=args[0]):
                proc = self.pudicus(*args)
                self.assertEqual(proc.returncode, 0, "Configured success code was rejected")
        self.assertIn("Inspection-result: clean", self.msg.read_text())
        self.assert_not_committed()

    def test_empty_failure_report_is_an_operational_error(self):
        command = self.script(
            "from pathlib import Path\nimport sys\n"
            "Path(sys.argv[1]).write_text('[]')\n"
            "sys.exit(1)\n"
        ) + " {report_file}"
        result = run_command_checker({"name": "synthetic", "command": command})
        self.assertFalse(result.clean)
        self.assertTrue(result.error, "Empty failure report was treated as approvable findings")

    def test_scanner_operational_error_blocks_and_suppresses_logs(self):
        sentinel = "synthetic-" + "private-diagnostic"
        command = self.script(
            "import sys\n"
            f"print({sentinel!r})\n"
            f"print({sentinel!r}, file=sys.stderr)\n"
            "sys.exit(2)\n"
        )
        self.policy(command)
        self.assert_blocked()
        proc = self.pudicus("check")
        self.assertTrue(sentinel not in proc.stdout + proc.stderr, "Raw scanner logs were exposed")

    def test_invalid_report_blocks_and_suppresses_logs(self):
        sentinel = "synthetic-" + "report-diagnostic"
        command = self.script(
            "from pathlib import Path\nimport sys\n"
            f"Path(sys.argv[1]).write_text({sentinel!r})\n"
            f"print({sentinel!r})\n"
            "sys.exit(1)\n"
        ) + " {report_file}"
        self.policy(command)
        self.assert_blocked()
        proc = self.pudicus("check")
        self.assertTrue(sentinel not in proc.stdout + proc.stderr, "Invalid report contents were exposed")

    def test_report_prints_only_file_and_rule_id(self):
        sentinel = "synthetic-" + "matched-material"
        report = [{
            "File": "fixture.txt", "RuleID": "synthetic-rule",
            "Match": sentinel, "Secret": sentinel, "Description": sentinel,
        }]
        command = self.script(
            "from pathlib import Path\nimport json, sys\n"
            f"Path(sys.argv[1]).write_text(json.dumps({report!r}))\n"
            f"print({sentinel!r})\n"
            f"print({sentinel!r}, file=sys.stderr)\n"
            "sys.exit(1)\n"
        ) + " {report_file}"
        self.policy(command)
        proc = self.pudicus("check")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("fixture.txt", proc.stderr)
        self.assertIn("synthetic-rule", proc.stderr)
        self.assertTrue(sentinel not in proc.stdout + proc.stderr, "Matched material was exposed")

    def test_staged_tree_changed_by_checker_is_blocked(self):
        command = self.script(
            "from pathlib import Path\nimport subprocess\n"
            "Path('fixture.txt').write_text('Changed during inspection.\\n')\n"
            "subprocess.run(['git', 'add', 'fixture.txt'], check=True)\n"
        )
        self.policy(command)
        for args in (("check",), ("hook", str(self.msg))):
            with self.subTest(command=args[0]):
                self.stage("Original staged content.\n")
                proc = self.pudicus(*args)
                self.assertNotEqual(proc.returncode, 0, "Changed staged tree passed inspection")
                self.assertNotIn("Inspection-sig:", self.msg.read_text())
                self.assert_not_committed()

    def test_tactus_operational_error_is_not_an_approval_finding(self):
        # Exercise the existing adapter contract without invoking Tactus.
        proc = subprocess.CompletedProcess([], 2, stdout="synthetic-log", stderr="synthetic-log")
        with mock.patch("pudicus.core.run_cmd", return_value=proc):
            result = run_tactus_checker({"name": "synthetic", "procedure": "fixture"})
        self.assertFalse(result.clean)
        self.assertTrue(result.error)
        self.assertTrue("synthetic-log" not in str(result.findings))

    def test_operational_error_cannot_be_interactively_overridden(self):
        failed = CheckerResult("synthetic", False, "Checker failed", error=True)
        with mock.patch.object(cli, "run_cmd") as git_cmd, \
                mock.patch.object(cli, "get_secret", return_value="synthetic-secret"), \
                mock.patch.object(cli, "get_tree_hash", return_value="same-tree"), \
                mock.patch.object(cli, "configured_checks", return_value=({}, [failed])), \
                mock.patch.object(cli.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(cli.getpass, "getpass") as prompt:
            git_cmd.return_value.stdout = str(self.repo)
            with self.assertRaises(SystemExit) as stopped:
                cli.cmd_hook(argparse.Namespace(commit_msg_file=str(self.msg)))
            self.assertNotEqual(stopped.exception.code, 0)
            prompt.assert_not_called()
        self.assertNotIn("Inspection-sig:", self.msg.read_text())

    def test_report_path_with_spaces_is_one_argument_and_is_removed(self):
        report_dir = self.root / "private reports with spaces"
        report_dir.mkdir()
        command = self.script(
            "from pathlib import Path\nimport json, sys\n"
            "assert len(sys.argv) == 2\n"
            "Path(sys.argv[1]).write_text(json.dumps(["
            "{'File': 'fixture.txt', 'RuleID': 'synthetic-rule'}]))\n"
            "sys.exit(1)\n"
        ) + " {report_file}"
        with mock.patch("tempfile.tempdir", str(report_dir)):
            result = run_command_checker({"name": "synthetic", "command": command})
        self.assertFalse(result.clean)
        self.assertFalse(result.error, "Report path was split at whitespace")
        self.assertEqual(result.findings, [{"File": "fixture.txt", "RuleID": "synthetic-rule"}])
        self.assertEqual(list(report_dir.iterdir()), [], "Temporary report was retained")


if __name__ == "__main__":
    unittest.main()
