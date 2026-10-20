"""Recorded per-finding overrides, using synthetic data and disposable repos."""

import re
import unittest

import yaml

from test_commit_gate import GITLEAKS, RepositoryFixture

# Flagged by the shipped personal-email rule; the rule allowlists only
# example.* and GitHub identities.
EMAIL = "info" + "@" + "public-role.test"
OTHER_EMAIL = "help" + "@" + "public-role.test"
PAGE = "page.tsx"
REASON = "Public role address for the site"


@unittest.skipUnless(GITLEAKS, "Gitleaks must be installed for actual scanner tests")
class RecordedOverrideTests(RepositoryFixture):
    def setUp(self):
        super().setUp()
        proc = self.leftblock("install", "--local", "--check-only", "--gitleaks", GITLEAKS)
        self.assertEqual(proc.returncode, 0, "Local install failed")

    def write_stage(self, text, name=PAGE):
        (self.repo / name).write_text(text)
        self.git("add", name, check=True)

    def check(self):
        policy = self.repo / ".git" / "leftblock" / "policy.json"
        return self.leftblock("check", "--config", str(policy))

    def ids(self, proc):
        return re.findall(r'"id": "([0-9a-f]{16})"', proc.stderr)

    def blocked_id(self, text=None):
        self.write_stage(text or f"a\nContact: {EMAIL}\n")
        proc = self.check()
        self.assertNotEqual(proc.returncode, 0)
        ids = self.ids(proc)
        self.assertEqual(len(ids), 1)
        return ids[0]

    def allow(self, *ids, reason=REASON):
        return self.leftblock("allow", *ids, "--reason", reason)

    def test_block_output_has_id_and_instructions_but_no_value(self):
        ident = self.blocked_id()
        proc = self.check()
        out = proc.stdout + proc.stderr
        self.assertIn(f"allow {ident}", out)
        self.assertIn("record a reviewed override", out)
        self.assertIn("--reason", out)
        self.assertNotIn(EMAIL, out)
        self.assertNotIn("public-role", out)
        self.assertNotIn("No approval override", out)

    def test_allow_stages_entry_then_check_passes_and_reports(self):
        ident = self.blocked_id()
        proc = self.allow(ident)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        staged = self.git("show", ":.leftblock-allow.yml", check=True).stdout
        data = yaml.safe_load(staged)
        self.assertEqual(data["version"], 1)
        entry = data["allow"][0]
        self.assertEqual(
            (entry["id"], entry["rule"], entry["file"], entry["reason"]),
            (ident, "leftblock-personal-email", PAGE, REASON),
        )
        self.assertNotIn(EMAIL, staged)
        check = self.check()
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn("Override applied", check.stderr)
        self.assertIn(ident, check.stderr)
        self.assertIn(REASON, check.stderr)
        # Overrides stay visible on every run, and the commit goes through.
        self.assertEqual(self.git("commit", "-m", "test: allowed").returncode, 0)

    def test_allow_file_itself_is_not_flagged_and_dedupes(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        self.assertEqual(self.allow(ident).returncode, 0)
        data = yaml.safe_load((self.repo / ".leftblock-allow.yml").read_text())
        self.assertEqual(len(data["allow"]), 1)
        scan = self.check()
        self.assertEqual(scan.returncode, 0, scan.stderr)
        # Not the hex id, but the file as a whole: a numeric-looking id stays a string.
        self.assertIsInstance(data["allow"][0]["id"], str)

    def test_new_email_in_same_file_still_blocks(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        self.write_stage(f"a\nContact: {EMAIL}\nAlso: {OTHER_EMAIL}\n")
        proc = self.check()
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(len(self.ids(proc)), 1)
        self.assertNotIn(ident, self.ids(proc))

    def test_changed_allowed_line_reblocks(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        self.write_stage(f"a\nWrite to: {EMAIL}\n")
        proc = self.check()
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn(ident, self.ids(proc))

    def test_line_numbers_inside_modified_committed_file(self):
        self.write_stage("one\ntwo\nthree\n")
        self.git("commit", "-m", "test: base", check=True)
        ident = self.blocked_id(f"one\ntwo\nthree\nContact: {EMAIL}\n")
        self.assertEqual(self.allow(ident).returncode, 0)
        proc = self.check()
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_reason_too_short_or_missing_is_refused(self):
        ident = self.blocked_id()
        for reason in ("", "   short  "):
            with self.subTest(reason=reason):
                proc = self.allow(ident, reason=reason)
                self.assertEqual(proc.returncode, 1)
        missing = self.leftblock("allow", ident)
        self.assertNotEqual(missing.returncode, 0)
        self.assertFalse((self.repo / ".leftblock-allow.yml").exists())

    def test_hand_edited_entry_with_empty_reason_blocks_as_invalid(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        path = self.repo / ".leftblock-allow.yml"
        data = yaml.safe_load(path.read_text())
        data["allow"][0]["reason"] = ""
        path.write_text(yaml.safe_dump(data))
        self.git("add", ".leftblock-allow.yml", check=True)
        proc = self.check()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Invalid .leftblock-allow.yml", proc.stderr)

    def test_invalid_allow_files_block_even_on_clean_content(self):
        self.write_stage("Harmless.\n")
        path = self.repo / ".leftblock-allow.yml"
        bad = (
            "version: [",
            "version: 2\nallow: []\n",
            "version: 1\nallow:\n  - rule: r\n    file: f\n    reason: long enough reason\n",
        )
        for text in bad:
            with self.subTest(text=text):
                path.write_text(text)
                self.git("add", ".leftblock-allow.yml", check=True)
                proc = self.check()
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("Invalid .leftblock-allow.yml", proc.stderr)

    def test_unstaged_allow_file_has_no_effect(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        self.git("reset", "-q", "--", ".leftblock-allow.yml", check=True)
        self.assertTrue((self.repo / ".leftblock-allow.yml").exists())
        proc = self.check()
        self.assertNotEqual(proc.returncode, 0)

    def test_unknown_id_is_refused(self):
        self.blocked_id()
        proc = self.allow("0123456789abcdef")
        self.assertEqual(proc.returncode, 1)
        self.assertFalse((self.repo / ".leftblock-allow.yml").exists())

    def test_allow_does_not_commit(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        self.assert_not_committed()


class OverrideNeverCoversErrorsTests(RepositoryFixture):
    def test_missing_scanner_is_not_overridden(self):
        self.stage(f"Contact: {EMAIL}\n")
        self.policy("definitely-missing-scanner-binary --scan")
        entry = {
            "version": 1,
            "allow": [{"id": "0123456789abcdef", "rule": "x", "file": "fixture.txt",
                       "reason": "A long enough reason."}],
        }
        (self.repo / ".leftblock-allow.yml").write_text(yaml.safe_dump(entry))
        self.git("add", ".leftblock-allow.yml", check=True)
        self.assertNotEqual(self.leftblock("check").returncode, 0)
        proc = self.leftblock("allow", "0123456789abcdef", "--reason", REASON)
        self.assertEqual(proc.returncode, 1)

    def test_error_result_with_matching_entry_stays_blocked(self):
        from leftblock.allow import apply_allowlist
        from leftblock.core import CheckerResult
        result = CheckerResult("s", False, [{"File": "f", "RuleID": "r", "id": "a" * 16}], error=True)
        entries = [{"id": "a" * 16, "rule": "r", "file": "f", "reason": "A long enough reason."}]
        self.assertEqual(apply_allowlist([result], entries), [])
        self.assertFalse(result.clean)


if __name__ == "__main__":
    unittest.main()
