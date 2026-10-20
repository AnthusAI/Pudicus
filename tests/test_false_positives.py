"""Regression tests: Kanbus ids with any project key, and merge-commit scope.

Fixtures are synthetic: UUIDs come from a seeded RNG.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_sensitive_rules import (
    GITLEAKS, RULESET, _rng, rand_hex, scan_and_rule_ids,
)

ROOT = Path(__file__).resolve().parents[1]


def _uuid(rng):
    return "-".join(rand_hex(rng, n) for n in (8, 4, 4, 4, 12))


def _issue(prefix, rng):
    return (
        '{\n  "id": "%s-%s",\n  "parent": "%s-%s",\n  "title": "T"\n}\n'
        % (prefix, _uuid(rng), prefix, _uuid(rng))
    )


@unittest.skipIf(GITLEAKS is None, "gitleaks binary not installed")
class KanbusIdTests(unittest.TestCase):
    def test_any_project_key_prefix_passes_in_structural_fields(self):
        rng = _rng()
        files = {
            "project/issues/%s.json" % p: _issue(p, rng)
            for p in ("kbs", "PPY", "virt", "kanbus", "BOTSPY")
        }
        self.assertEqual(scan_and_rule_ids(files), [])

    def test_bare_session_uuid_is_still_flagged(self):
        rng = _rng()
        u = _uuid(rng)
        self.assertEqual(scan_and_rule_ids({"notes.md": "session %s here\n" % u}),
                         ["pudicus-session-uuid"])
        self.assertEqual(scan_and_rule_ids({"a.json": '{"session_id": "%s"}\n' % u}),
                         ["pudicus-session-uuid"])
        # A prefixed uuid outside the structural fields is no longer waved through.
        self.assertEqual(scan_and_rule_ids({"b.md": "see kbs-%s\n" % u}),
                         ["pudicus-session-uuid"])


@unittest.skipIf(GITLEAKS is None, "gitleaks binary not installed")
class MergeScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update({
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "PYTHONPATH": str(ROOT),
        })
        self.git("init", "-q", "-b", "main")
        for k, v in (("user.name", "T"), ("user.email", "t@example.com"),
                     ("commit.gpgSign", "false")):
            self.git("config", k, v)
        rules = Path(self.temp.name) / "rules.toml"
        shutil.copyfile(RULESET, rules)
        policy = {"version": 1, "checkers": [{
            "name": "gitleaks", "type": "command",
            "command": "%s protect --staged --config %s --redact --no-banner "
                       "--report-format json --report-path {report_file}" % (GITLEAKS, rules),
            "success_codes": [0], "finding_codes": [1],
        }]}
        self.policy = Path(self.temp.name) / "policy.json"
        self.policy.write_text(json.dumps(policy))
        self.rng = _rng()

    def git(self, *args, check=True):
        return subprocess.run(["git", *args], cwd=self.repo, env=self.env,
                              text=True, capture_output=True, check=check)

    def check(self):
        return subprocess.run(
            [sys.executable, "-m", "leftblock.cli", "check", "--config", str(self.policy)],
            cwd=self.repo, env=self.env, text=True, capture_output=True)

    def write(self, name, text):
        p = self.repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        self.git("add", name)

    def flagged(self):
        return "session %s here\n" % _uuid(self.rng)

    def setup_branches(self):
        self.write("base.txt", "base\n")
        self.git("commit", "-qm", "base")
        self.git("checkout", "-qb", "feature")
        self.write("feature.txt", "feature\n")
        self.git("commit", "-qm", "feature")
        self.git("checkout", "-q", "main")
        self.write("main.txt", "main\n")
        self.git("commit", "-qm", "main")

    def test_plain_commit_with_flagged_line_is_still_blocked(self):
        self.write("a.txt", self.flagged())
        self.assertEqual(self.check().returncode, 1)

    def test_merge_of_already_public_flagged_content_is_allowed(self):
        self.git("checkout", "-qb", "develop")
        self.write("base.txt", "base\n")
        self.git("commit", "-qm", "base")
        self.git("checkout", "-qb", "feature")
        self.write("feature.txt", "feature\n")
        self.git("commit", "-qm", "feature")
        self.git("checkout", "-q", "develop")
        flagged = self.flagged()
        self.write("dev.txt", flagged)
        self.write("shared.txt", "one\n" + flagged)
        self.git("commit", "-qm", "develop adds flagged content")
        self.git("checkout", "-q", "feature")
        # Without a merge in progress the same staged change is blocked.
        self.git("merge", "--no-commit", "--no-ff", "develop")
        self.assertTrue((self.repo / ".git" / "MERGE_HEAD").exists())
        proc = self.check()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.git("commit", "-qm", "merge develop")

    def test_merge_resolution_adding_a_new_flagged_line_is_blocked(self):
        self.git("checkout", "-qb", "develop")
        self.write("shared.txt", "one\n")
        self.git("commit", "-qm", "base")
        self.git("checkout", "-qb", "feature")
        self.write("shared.txt", "one\nfeature\n")
        self.git("commit", "-qm", "feature")
        self.git("checkout", "-q", "develop")
        self.write("shared.txt", "one\ndevelop\n" + self.flagged())
        self.git("commit", "-qm", "develop")
        self.git("checkout", "-q", "feature")
        self.git("merge", "--no-commit", "--no-ff", "develop", check=False)
        self.write("shared.txt", "one\nfeature\ndevelop\n" + self.flagged()
                   + "resolved " + self.flagged())
        proc = self.check()
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("shared.txt", proc.stderr)

    def test_merge_new_file_and_rename_handling(self):
        self.git("checkout", "-qb", "develop")
        flagged = self.flagged()
        self.write("old.txt", "a\nb\nc\nd\ne\nf\n" + flagged)
        self.git("commit", "-qm", "base")
        self.git("checkout", "-qb", "feature")
        self.git("mv", "old.txt", "new.txt")
        self.git("commit", "-qm", "rename")
        self.git("checkout", "-q", "develop")
        self.write("old.txt", "a\nb\nc\nd\ne\nf\n" + flagged + "g\n")
        self.git("commit", "-qm", "edit")
        self.git("checkout", "-q", "feature")
        self.git("merge", "--no-commit", "--no-ff", "develop", check=False)
        self.assertEqual(self.check().returncode, 0)
        # A brand-new file in the resolution is scanned in full.
        self.write("extra.txt", self.flagged())
        self.assertEqual(self.check().returncode, 1)
