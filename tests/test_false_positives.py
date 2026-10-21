"""Regression tests: narrow board bookkeeping and conservative merge scope.

Fixtures are synthetic: UUIDs come from a seeded RNG.
"""

import json
import os
import hashlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from leftblock import cli, core, merge

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
                         ["leftblock-session-uuid"])
        self.assertEqual(scan_and_rule_ids({"a.json": '{"session_id": "%s"}\n' % u}),
                         ["leftblock-session-uuid"])

    def test_prefixed_ids_in_prose_remain_detected(self):
        rng = _rng()
        files = {
            "doc%d.md" % i: "see %s-%s for details\n" % (p, _uuid(rng))
            for i, p in enumerate(("kbs", "PPY", "kanbus", "BOTSPY"))
        }
        self.assertEqual(scan_and_rule_ids(files), ["leftblock-session-uuid"])

    def test_bare_uuid_in_prose_is_flagged_next_to_nothing_prefixed(self):
        self.assertEqual(
            scan_and_rule_ids({"c.md": "id %s\n" % _uuid(_rng())}),
            ["leftblock-session-uuid"])

    def test_prefix_does_not_hide_another_uuid_on_the_same_line(self):
        rng = _rng()
        self.assertIn("leftblock-session-uuid", scan_and_rule_ids({
            "notes.md": "see PPY-%s; session %s\n" % (_uuid(rng), _uuid(rng)),
        }))

    def test_prefixed_session_value_is_not_structural_bookkeeping(self):
        self.assertIn("leftblock-session-uuid", scan_and_rule_ids({
            "project/events/synthetic.json": json.dumps({
                "session_id": "PPY-" + _uuid(_rng()),
            }, indent=2),
        }))


def _uuid4(rng):
    return "%s-%s-4%s-%s%s-%s" % (
        rand_hex(rng, 8), rand_hex(rng, 4), rand_hex(rng, 3),
        rng.choice("89ab"), rand_hex(rng, 3), rand_hex(rng, 12))


@unittest.skipIf(GITLEAKS is None, "gitleaks binary not installed")
class KanbusProjectIdTests(unittest.TestCase):
    def _yml(self, body):
        return scan_and_rule_ids({".kanbus.yml": body})

    def test_top_level_project_id_passes(self):
        rng = _rng()
        self.assertEqual(self._yml(
            "project_key: kbs\nproject_id: %s\n" % _uuid4(rng)), [])
        self.assertEqual(scan_and_rule_ids({
            "sub/.kanbus.yml": "project_id: %s  \n" % _uuid4(rng)}), [])

    def test_indented_project_id_is_flagged(self):
        self.assertEqual(self._yml(
            "realtime:\n  project_id: %s\n" % _uuid4(_rng())),
            ["leftblock-session-uuid"])

    def test_other_key_in_kanbus_yml_is_flagged(self):
        self.assertEqual(self._yml("session_id: %s\n" % _uuid4(_rng())),
                         ["leftblock-session-uuid"])

    def test_project_id_outside_kanbus_yml_is_flagged(self):
        self.assertEqual(scan_and_rule_ids({
            "config.yml": "project_id: %s\n" % _uuid4(_rng())}),
            ["leftblock-session-uuid"])

    def test_non_v4_uuid_is_flagged(self):
        # Version nibble 1, not 4: only UUID v4 project ids are exempt.
        rng = _rng()
        v1 = "%s-%s-1%s-a%s-%s" % (rand_hex(rng, 8), rand_hex(rng, 4),
                                   rand_hex(rng, 3), rand_hex(rng, 3),
                                   rand_hex(rng, 12))
        self.assertEqual(self._yml("project_id: %s\n" % v1),
                         ["leftblock-session-uuid"])


@unittest.skipIf(GITLEAKS is None, "gitleaks binary not installed")
class MergeScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.env = {
            k: v for k, v in os.environ.items()
            if not k.startswith(("GIT_", "GITLEAKS_", "LEFTBLOCK_"))
        }
        self.env.update({
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "PYTHONPATH": str(ROOT),
            "LEFTBLOCK_SECRET_PATH": str(Path(self.temp.name) / "absent-secret"),
        })
        self.git("init", "-q", "-b", "main", "--template=")
        for k, v in (("user.name", "T"), ("user.email", "t@example.com"),
                     ("commit.gpgSign", "false")):
            self.git("config", k, v)
        rules = Path(self.temp.name) / "rules.toml"
        shutil.copyfile(RULESET, rules)
        policy = {"version": 1, "checkers": [{
            "name": "gitleaks", "type": "command",
            "command": shlex.join([
                GITLEAKS, "protect", "--staged", "--config", str(rules),
                "--redact", "--no-banner", "--report-format", "json",
                "--report-path", "{report_file}",
            ]),
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

    def test_unchanged_same_path_parent_content_is_not_rescanned(self):
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
        # Both imported files exactly match the non-HEAD parent at these paths.
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

    def start_merge(self, imported=None):
        self.write("base.txt", "base\n")
        self.git("commit", "-qm", "base")
        self.git("checkout", "-qb", "feature")
        self.write("imported.txt", imported or "inherited fixture\n")
        self.git("commit", "-qm", "feature")
        self.git("checkout", "-q", "main")
        self.write("main.txt", "main\n")
        self.git("commit", "-qm", "main")
        self.git("merge", "--no-commit", "--no-ff", "feature")

    def configured(self):
        with mock.patch.dict(os.environ, self.env, clear=True):
            return cli.configured_checks(str(self.repo), str(self.policy))[1]

    def snapshot(self):
        # Only this disposable fixture is inspected.
        return {
            str(path.relative_to(self.repo)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.repo.rglob("*") if path.is_file() and not path.is_symlink()
        }

    def test_renaming_board_attribution_to_other_context_is_blocked(self):
        event = json.dumps({"actor_id": _uuid(self.rng)}, indent=2) + "\n"
        self.write("project/events/event.json", event)
        self.git("commit", "-qm", "board attribution")
        self.git("checkout", "-qb", "feature")
        self.write("feature.txt", "feature\n")
        self.git("commit", "-qm", "feature")
        self.git("checkout", "-q", "main")
        self.write("main.txt", "main\n")
        self.git("commit", "-qm", "main")
        self.git("merge", "--no-commit", "--no-ff", "feature")
        self.git("mv", "project/events/event.json", "telemetry.json")
        before = self.git("rev-parse", "HEAD").stdout
        result = self.check()
        self.assertEqual(result.returncode, 1, "A renamed path inherited a board-only exception")
        self.assertIn("leftblock-session-uuid", result.stderr)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout, before)

    def test_new_context_assembled_from_existing_parent_lines_is_blocked(self):
        # Each line exists in a parent, but the new adjacency does not. The
        # old line-removal algorithm discarded every line and skipped this.
        start, middle, end = "SYNTHETIC_BEGIN", "fixture_payload", "SYNTHETIC_END"
        self.write("assembled.txt", "baseline\n")
        self.git("commit", "-qm", "base")
        self.git("checkout", "-qb", "feature")
        self.write("assembled.txt", start + "\nbreak\n" + middle + "\nbreak\n" + end + "\n")
        self.git("commit", "-qm", "separate pieces")
        self.git("checkout", "-q", "main")
        self.write("main.txt", "main\n")
        self.git("commit", "-qm", "main")
        self.git("merge", "--no-commit", "--no-ff", "feature")
        self.write("assembled.txt", start + "\n" + middle + "\n" + end + "\n")
        rules = Path(self.temp.name) / "multiline.toml"
        rules.write_text(
            "[[rules]]\nid = \"synthetic-multiline\"\n"
            "description = \"Generated multiline fixture\"\n"
            "regex = '''" + start + "\\n" + middle + "\\n" + end + "'''\n"
        )
        policy = json.loads(self.policy.read_text())
        argv = shlex.split(policy["checkers"][0]["command"])
        argv[argv.index("--config") + 1] = str(rules)
        policy["checkers"][0]["command"] = shlex.join(argv)
        self.policy.write_text(json.dumps(policy))
        result = self.check()
        self.assertEqual(result.returncode, 1, "New multiline context was skipped")
        self.assertIn("synthetic-multiline", result.stderr)

    def test_modified_imported_file_keeps_inherited_findings(self):
        self.start_merge(self.flagged())
        with (self.repo / "imported.txt").open("a") as stream:
            stream.write("resolution adds a harmless line\n")
        self.git("add", "imported.txt")
        self.assertEqual(self.check().returncode, 1)

    def test_missing_or_invalid_parent_falls_back_to_full_scan(self):
        self.start_merge(self.flagged())
        merge_head = self.repo / ".git" / "MERGE_HEAD"
        original = merge_head.read_bytes()
        cases = (
            b"not-an-object\n",
            b"f" * 40 + b"\n",
            self.git("rev-parse", "HEAD^{tree}").stdout.encode(),
            b"",
        )
        for value in cases:
            with self.subTest(kind=len(value)):
                merge_head.write_bytes(value)
                self.assertEqual(self.check().returncode, 1)
        merge_head.unlink()
        self.assertEqual(self.check().returncode, 1)
        merge_head.write_bytes(original)

    def test_forced_scope_failure_runs_original_index_and_cleans_temporary_file(self):
        self.start_merge(self.flagged())
        original = merge._git
        seen = []
        create = merge.tempfile.mkstemp

        def create_index(*args, **kwargs):
            result = create(*args, **kwargs)
            seen.append(result[1])
            return result

        def fail_update(repo, *args, **kwargs):
            if "update-index" in args:
                raise merge.MergeScopeError("Synthetic failure")
            return original(repo, *args, **kwargs)

        with mock.patch.object(merge.tempfile, "mkstemp", side_effect=create_index), \
                mock.patch.object(merge, "_git", side_effect=fail_update):
            results = self.configured()
        self.assertTrue(any(not result.clean for result in results))
        self.assertTrue(seen)
        self.assertTrue(all(not Path(path).exists() for path in seen))

    def test_scope_builder_does_not_write_real_index_objects_or_worktree(self):
        self.start_merge(self.flagged())
        before = self.snapshot()
        with mock.patch.dict(os.environ, self.env, clear=True):
            state = merge.merge_state(str(self.repo))
            scoped = merge.build_scoped_index(str(self.repo), state[1], head=state[0])
        try:
            self.assertEqual(self.snapshot(), before)
        finally:
            os.remove(scoped)

    def test_changed_binary_and_submodule_entries_are_retained(self):
        self.start_merge()
        binary = self.repo / "payload.bin"
        binary.write_bytes(b"generated\0binary")
        self.git("add", "payload.bin")
        parent = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("update-index", "--add", "--cacheinfo", "160000", parent, "module")
        with mock.patch.dict(os.environ, self.env, clear=True):
            state = merge.merge_state(str(self.repo))
            scoped = merge.build_scoped_index(str(self.repo), state[1], head=state[0])
            try:
                entries = merge.index_entries(str(self.repo), scoped)
            finally:
                os.remove(scoped)
        self.assertIn(b"payload.bin", entries)
        self.assertEqual(entries[b"module"], (b"160000", parent.encode()))

    def test_mode_change_and_symlink_are_not_parent_blob_exemptions(self):
        self.start_merge(self.flagged())
        self.git("update-index", "--chmod=+x", "imported.txt")
        (self.repo / "link").symlink_to("imported.txt")
        self.git("add", "link")
        with mock.patch.dict(os.environ, self.env, clear=True):
            state = merge.merge_state(str(self.repo))
            scoped = merge.build_scoped_index(str(self.repo), state[1], head=state[0])
            try:
                entries = merge.index_entries(str(self.repo), scoped)
            finally:
                os.remove(scoped)
        self.assertEqual(entries[b"imported.txt"][0], b"100755")
        self.assertEqual(entries[b"link"][0], b"120000")

    def test_octopus_merge_preserves_new_resolution_detection(self):
        self.write("base.txt", "base\n")
        self.git("commit", "-qm", "base")
        for branch in ("one", "two"):
            self.git("checkout", "-qb", branch, "main")
            self.write(branch + ".txt", self.flagged())
            self.git("commit", "-qm", branch)
        self.git("checkout", "-q", "main")
        self.write("main.txt", "main\n")
        self.git("commit", "-qm", "main")
        self.git("merge", "--no-commit", "--no-ff", "one", "two")
        self.assertEqual(len((self.repo / ".git" / "MERGE_HEAD").read_text().splitlines()), 2)
        self.assertEqual(self.check().returncode, 0)
        self.write("resolution.txt", self.flagged())
        self.assertEqual(self.check().returncode, 1)

    def test_command_mutating_private_index_cannot_report_clean(self):
        self.start_merge()
        self.write("resolution.txt", self.flagged())
        policy = json.loads(self.policy.read_text())
        policy["checkers"].insert(0, {
            "name": "synthetic-index-mutation", "type": "command",
            "command": shlex.join(["git", "update-index", "--force-remove", "resolution.txt"]),
        })
        self.policy.write_text(json.dumps(policy))
        before = self.git("ls-files", "-s").stdout
        result = self.check()
        self.assertEqual(result.returncode, 2, "A checker changed the inspected index undetected")
        self.assertIn("merge-scope", result.stderr)
        self.assertEqual(self.git("ls-files", "-s").stdout, before)

    def test_merge_parent_change_during_checker_blocks(self):
        self.start_merge()
        with mock.patch.object(cli, "execute_checkers", return_value=[core.CheckerResult("test", True)]), \
                mock.patch.object(cli, "merge_state", side_effect=[
                    ("HEAD", tuple((self.repo / ".git" / "MERGE_HEAD").read_text().splitlines())),
                    None,
                ]):
            results = self.configured()
        self.assertTrue(any(result.error for result in results))

    def test_split_index_scope_is_safe_or_falls_back(self):
        self.start_merge(self.flagged())
        self.git("update-index", "--split-index")
        before = self.snapshot()
        results = self.configured()
        # Git versions differ in resolving an external split-index copy. It
        # must either scope safely or run the original full staged scan.
        self.assertTrue(all(isinstance(result, core.CheckerResult) for result in results))
        self.assertEqual(self.snapshot(), before)

    def test_relative_alternate_index_from_subdirectory_is_respected(self):
        self.start_merge()
        original_index = (self.repo / ".git" / "index").read_bytes()
        subdir = self.repo / "subdirectory"
        subdir.mkdir()
        alternate = subdir / "alternate-index"
        alternate.write_bytes(original_index)
        alternate_env = dict(self.env, GIT_INDEX_FILE=str(alternate))
        (self.repo / "alternate.txt").write_text(self.flagged())
        staged = subprocess.run(
            ["git", "add", "alternate.txt"], cwd=self.repo, env=alternate_env, capture_output=True,
        )
        self.assertEqual(staged.returncode, 0)
        result = subprocess.run(
            [sys.executable, "-m", "leftblock.cli", "check", "--config", str(self.policy)],
            cwd=subdir, env=dict(self.env, GIT_INDEX_FILE="alternate-index"),
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("leftblock-session-uuid", result.stderr)
        self.assertEqual((self.repo / ".git" / "index").read_bytes(), original_index)

    def test_receipt_signs_real_tree_and_temporary_index_is_removed(self):
        self.start_merge(self.flagged())
        secret = Path(self.env["LEFTBLOCK_SECRET_PATH"])
        secret.write_text("synthetic-merge-receipt-key")
        shutil.copyfile(self.policy, self.repo / ".leftblock.yml")
        message = Path(self.temp.name) / "message.txt"
        message.write_text("Synthetic merge fixture\n")
        real_tree = self.git("write-tree").stdout.strip()
        result = subprocess.run(
            [sys.executable, "-m", "leftblock.cli", "hook", str(message)],
            cwd=self.repo, env=self.env, text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Inspection-tree: " + real_tree, message.read_text())
        self.assertIn("Inspected-by: leftblock-v1", message.read_text())
        self.assertEqual(self.git("write-tree").stdout.strip(), real_tree)


class ScopeParsingTests(unittest.TestCase):
    def test_malformed_and_unmerged_entries_raise_scope_error(self):
        oid = b"a" * 40
        for data in (
            b"malformed",
            b"100644 " + oid + b" 2\tfile\0",
            b"100644 " + oid + b" 0\tfile\0" + b"100644 " + oid + b" 0\tfile\0",
            b"100644 invalid 0\tfile\0",
            b"100644 " + oid + b" 0\t\0",
        ):
            with self.subTest(length=len(data)):
                with self.assertRaises(merge.MergeScopeError):
                    merge._parse_ls(data, staged=True)

    def test_command_gets_scope_but_tactus_keeps_full_index(self):
        checkers = [
            {"name": "command", "type": "command", "command": "true"},
            {"name": "tactus", "type": "tactus", "procedure": "synthetic"},
        ]
        env = {"GIT_INDEX_FILE": "/synthetic/private-index"}
        with mock.patch.object(core, "run_command_checker", return_value=core.CheckerResult("command", True)) as command, \
                mock.patch.object(core, "run_tactus_checker", return_value=core.CheckerResult("tactus", True)) as tactus:
            core.execute_checkers(checkers, cwd="/synthetic/repo", env=env)
        command.assert_called_once_with(checkers[0], cwd="/synthetic/repo", env=env)
        tactus.assert_called_once_with(checkers[1], cwd="/synthetic/repo")
