"""Silent Gitleaks bypasses (inline allow markers, .gitleaksignore) and override receipts."""

import json
import re
import subprocess
import unittest
from importlib.metadata import version

from leftblock import bypass
from test_commit_gate import GITLEAKS, RepositoryFixture

MARKER = "gitleaks" + ":allow"
EMAIL = "info" + "@" + "public-role.test"
REASON = "Reviewed: documentation example, not a real finding"


class DiffParsingTests(unittest.TestCase):
    def test_added_lines_are_numbered_and_headers_cannot_be_forged(self):
        diff = (
            b"diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n"
            b"@@ -3 +3,2 @@\n-old\n+++ b/forged.txt\n+# " + MARKER.encode() + b"\n"
            b"@@ -9,0 +10 @@\n+tail\n"
            b"diff --git a/gone b/gone\n--- a/gone\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
        )
        self.assertEqual(list(bypass._added_lines(diff)), [
            ("a.txt", 3, b"++ b/forged.txt"),
            ("a.txt", 4, b"# " + MARKER.encode()),
            ("a.txt", 10, b"tail"),
        ])

    def test_quoted_paths_are_decoded(self):
        self.assertEqual(bypass._unquote(b'"b/a\\tb\\"c\\303\\251"'), b'b/a\tb"c\xc3\xa9')


@unittest.skipUnless(GITLEAKS, "Gitleaks must be installed for actual scanner tests")
class BypassTests(RepositoryFixture):
    def setUp(self):
        super().setUp()
        proc = self.leftblock("install", "--local", "--check-only", "--gitleaks", GITLEAKS)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def write_stage(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        self.git("add", name, check=True)

    def check_json(self):
        proc = self.leftblock("check", "--format", "json")
        return proc, json.loads(proc.stdout)

    def allow(self, *ids):
        return self.leftblock("allow", *ids, "--reason", REASON)

    # (a) inline allow markers

    def test_marker_line_blocks_with_its_line_number_and_can_be_overridden(self):
        self.write_stage("notes.md", f"one\ntwo\n# harmless {MARKER}\n")
        proc, report = self.check_json()
        self.assertEqual(proc.returncode, 1, proc.stderr)
        [finding] = report["findings"]
        self.assertEqual((finding["file"], finding["line"], finding["rule"]),
                         ("notes.md", 3, "leftblock-gitleaks-allow-marker"))
        self.assertRegex(finding["id"], r"^[0-9a-f]{16}$")
        self.assertIn("notes.md:3: leftblock-gitleaks-allow-marker", proc.stderr)
        self.assertEqual(self.allow(finding["id"]).returncode, 0)
        proc, report = self.check_json()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(report["overrides_applied"][0]["rule"], "leftblock-gitleaks-allow-marker")
        self.assertEqual(self.git("commit", "-m", "test: reviewed marker").returncode, 0)

    def test_changing_the_overridden_marker_line_blocks_again(self):
        self.write_stage("notes.md", f"# {MARKER}\n")
        _, report = self.check_json()
        self.assertEqual(self.allow(report["findings"][0]["id"]).returncode, 0)
        self.write_stage("notes.md", f"# {MARKER} (edited)\n")
        self.assertEqual(self.leftblock("check").returncode, 1)

    def test_only_added_lines_count_and_removal_is_fine(self):
        (self.repo / "notes.md").write_text(f"one # {MARKER}\ntwo\n")
        self.git("add", "notes.md", check=True)
        self.assertEqual(self.git("commit", "--no-verify", "-m", "test: pre-existing marker").returncode, 0)
        # Untouched marker line: only the new line is inspected.
        self.write_stage("notes.md", f"one # {MARKER}\ntwo\nthree\n")
        self.assertEqual(self.leftblock("check").returncode, 0)
        # Removing the marker is the fix, not a finding.
        self.write_stage("notes.md", "one\ntwo\nthree\n")
        self.assertEqual(self.leftblock("check").returncode, 0)
        # A new marker line is.
        self.write_stage("notes.md", f"one\ntwo\nthree # {MARKER}\n")
        proc = self.leftblock("check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("notes.md:3:", proc.stderr)

    def test_marker_does_not_hide_a_real_finding_on_the_same_line_from_the_report(self):
        self.write_stage("notes.md", f"mail {EMAIL} # {MARKER}\n")
        proc = self.leftblock("check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("leftblock-gitleaks-allow-marker", proc.stderr)
        self.assertNotIn(EMAIL, proc.stdout + proc.stderr)

    # (b) .gitleaksignore changes

    def test_staged_gitleaksignore_blocks_at_any_path_and_can_be_overridden(self):
        self.write_stage(".gitleaksignore", "a.txt:some-rule:1\n")
        self.write_stage("sub/dir/.gitleaksignore", "b.txt:some-rule:2\n")
        proc, report = self.check_json()
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(
            sorted((f["file"], f["rule"]) for f in report["findings"]),
            [(".gitleaksignore", "leftblock-gitleaksignore-change"),
             ("sub/dir/.gitleaksignore", "leftblock-gitleaksignore-change")],
        )
        self.assertEqual(self.allow(*[f["id"] for f in report["findings"]]).returncode, 0)
        self.assertEqual(self.leftblock("check").returncode, 0)
        self.assertEqual(self.git("commit", "-m", "test: reviewed ignore file").returncode, 0)
        # Editing the file re-blocks it; deleting it does not.
        self.write_stage(".gitleaksignore", "a.txt:some-rule:1\nc.txt:some-rule:3\n")
        self.assertEqual(self.leftblock("check").returncode, 1)
        self.git("rm", "-q", "-f", ".gitleaksignore", check=True)
        self.git("reset", "-q", "--", "sub", check=True)
        self.assertEqual(self.leftblock("check").returncode, 0)

    # (c) residual risk, pinned so a Gitleaks change is noticed

    def test_existing_committed_gitleaksignore_still_suppresses_and_no_flag_disables_it(self):
        self.write_stage("page.txt", f"a\nContact: {EMAIL}\n")
        report = self.root / "report.json"
        rules = self.repo / ".git" / "leftblock" / "gitleaks.toml"
        empty = self.root / "empty-ignore"
        empty.write_text("")

        def gitleaks(*extra):
            return subprocess.run(
                [GITLEAKS, "protect", "--staged", "--config", str(rules), "--no-banner",
                 "--redact", "--report-format", "json", "--report-path", str(report), *extra],
                cwd=self.repo, env=self.env, capture_output=True, text=True,
            ).returncode

        self.assertEqual(gitleaks(), 1)
        (self.repo / ".gitleaksignore").write_text("page.txt:leftblock-personal-email:2\n")
        self.assertEqual(gitleaks(), 0, "Gitleaks no longer honours a root .gitleaksignore")
        # An empty --gitleaks-ignore-path adds sources; it does not turn the root file off.
        self.assertEqual(gitleaks("--gitleaks-ignore-path", str(empty)), 0)
        self.assertEqual(gitleaks("--gitleaks-ignore-path", str(self.root)), 0)

    # (d) receipt mode

    def test_receipt_records_allowed_count_for_staged_overrides_without_a_passphrase(self):
        proc = self.leftblock("install")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.write_stage("page.txt", f"a\nContact: {EMAIL}\n")
        blocked = self.git("commit", "-m", "test: sensitive")
        self.assertNotEqual(blocked.returncode, 0)
        [ident] = re.findall(r"\[id ([0-9a-f]{16})\]", blocked.stderr)[:1]
        self.assertEqual(self.allow(ident).returncode, 0)
        done = self.git("commit", "-m", "test: allowed")
        self.assertEqual(done.returncode, 0, done.stderr)
        message = self.git("log", "-1", "--format=%B", check=True).stdout
        self.assertIn("Inspection-result: allowed:1\n", message)
        self.assertNotIn("Inspection-result: clean", message)
        self.assertNotIn("override:", message)
        self.assertEqual(self.leftblock("verify", "HEAD").returncode, 0)

    def test_receipt_stays_clean_without_overrides(self):
        self.assertEqual(self.leftblock("install").returncode, 0)
        self.write_stage("page.txt", "nothing sensitive\n")
        self.assertEqual(self.git("commit", "-m", "test: clean").returncode, 0)
        self.assertIn("Inspection-result: clean\n", self.git("log", "-1", "--format=%B").stdout)


if __name__ == "__main__":
    unittest.main()
