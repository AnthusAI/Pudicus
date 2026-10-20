"""Local baseline tests use disposable repos and an offline, tiny Python env."""

import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import venv
import yaml

from leftblock.hooks import install_local_check_hook, validate_local_check_install


ROOT = Path(__file__).resolve().parents[1]
GITLEAKS = shutil.which("gitleaks")


class LocalInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime_temp = tempfile.TemporaryDirectory()
        cls.runtime = Path(cls.runtime_temp.name) / "runtime"
        # No pip bootstrap or network: reuse already installed PyYAML. A nested
        # venv inherits base-site packages, not necessarily its parent's deps.
        venv.EnvBuilder(with_pip=False, system_site_packages=True).create(cls.runtime)
        cls.python = cls.runtime / "bin" / "python"
        packages = next((cls.runtime / "lib").glob("python*/site-packages"))
        for name in ("leftblock",):
            shutil.copytree(
                ROOT / name, packages / name,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
        shutil.copytree(
            Path(yaml.__file__).parent, packages / "yaml",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )

    @classmethod
    def tearDownClass(cls):
        cls.runtime_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update({
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LEFTBLOCK_SECRET_PATH": str(Path(self.temp.name) / "must-not-be-created"),
        })
        self.environment = patch.dict(os.environ, self.env, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.git("init", "--template=")
        self.git("config", "user.name", "Synthetic Tester")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "commit.gpgSign", "false")
        self.hook = self.repo / ".git" / "hooks" / "pre-commit"

    def git(self, *args, check=True):
        return subprocess.run(
            ["git", *args], cwd=self.repo, env=self.env,
            check=check, capture_output=True, text=True,
        )

    def install(self, scanner=None):
        with patch("sys.executable", str(self.python)):
            return install_local_check_hook(self.repo, scanner or GITLEAKS or "/usr/bin/true")

    def cli(self, *args):
        return subprocess.run(
            [str(self.python), "-I", "-m", "leftblock.cli", *args],
            cwd=self.repo, env=self.env, text=True, capture_output=True,
        )

    def test_local_install_changes_only_git_metadata_and_no_secret(self):
        (self.repo / ".leftblock.yml").write_text("owner policy must remain unchanged\n")
        hooks = self.hook.parent
        hooks.mkdir()
        existing = hooks / "commit-msg"
        existing.write_text("#!/bin/sh\n# owner's existing hook\nexit 0\n")
        existing.chmod(0o755)
        before_policy = (self.repo / ".leftblock.yml").read_bytes()
        before_hook = existing.read_bytes()
        before_status = self.git("status", "--porcelain=v1", "-z").stdout
        self.install()
        self.assertEqual(before_status, self.git("status", "--porcelain=v1", "-z").stdout)
        self.assertEqual(before_policy, (self.repo / ".leftblock.yml").read_bytes())
        self.assertEqual(before_hook, existing.read_bytes())
        self.assertFalse(Path(self.env["LEFTBLOCK_SECRET_PATH"]).exists())
        self.assertIn("-I -B -m leftblock.cli check --config", self.hook.read_text())
        paths = validate_local_check_install(self.repo)
        state = json.loads(paths["state"].read_text())
        self.assertEqual(state["policy_sha256"], hashlib.sha256(paths["policy"].read_bytes()).hexdigest())
        self.assertEqual(paths["policy"].stat().st_mode & 0o777, 0o600)

    def test_local_install_idempotence_and_edited_policy_preservation(self):
        self.install()
        paths = validate_local_check_install(self.repo)
        before = {name: (p.read_bytes(), p.stat().st_mtime_ns) for name, p in paths.items()}
        self.install()
        self.assertEqual(before, {name: (p.read_bytes(), p.stat().st_mtime_ns) for name, p in paths.items()})
        paths["policy"].write_text('{"owner":"changed"}\n')
        with self.assertRaisesRegex(ValueError, "edited"):
            self.install()
        self.assertEqual(paths["policy"].read_text(), '{"owner":"changed"}\n')

    def test_foreign_precommit_and_configured_hook_manager_are_preserved(self):
        self.hook.parent.mkdir()
        self.hook.write_text("#!/bin/sh\nexit 7\n")
        self.hook.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "unmanaged"):
            self.install()
        self.assertEqual(self.hook.read_text(), "#!/bin/sh\nexit 7\n")
        self.assertFalse((self.repo / ".git" / "leftblock").exists())
        self.hook.unlink()
        self.git("config", "core.hooksPath", ".husky/_")
        with self.assertRaisesRegex(ValueError, "core.hooksPath"):
            self.install()
        self.assertFalse(self.hook.exists())

    def test_disabled_managed_hook_and_symlink_policy_are_preserved(self):
        self.install()
        paths = validate_local_check_install(self.repo)
        self.hook.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "disabled"):
            self.install()
        self.hook.chmod(0o755)
        paths["policy"].unlink()
        target = Path(self.temp.name) / "owner"
        target.write_text("owner content\n")
        paths["policy"].symlink_to(target)
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.install()
        self.assertEqual(target.read_text(), "owner content\n")

    def test_unknown_policy_and_missing_scanner_cannot_be_overwritten(self):
        directory = self.repo / ".git" / "leftblock"
        directory.mkdir()
        policy = directory / "policy.json"
        policy.write_text("owner content\n")
        with self.assertRaisesRegex(ValueError, "unmanaged"):
            self.install()
        self.assertEqual(policy.read_text(), "owner content\n")
        policy.unlink()
        with self.assertRaisesRegex(ValueError, "Gitleaks"):
            self.install("/nonexistent-synthetic-gitleaks")
        self.assertFalse(self.hook.exists())

    def test_linked_worktree_shares_local_baseline(self):
        self.git("commit", "--allow-empty", "-m", "initial")
        linked = Path(self.temp.name) / "linked"
        self.git("worktree", "add", "-b", "linked", str(linked))
        with patch("sys.executable", str(self.python)):
            install_local_check_hook(linked, GITLEAKS or "/usr/bin/true")
        paths = validate_local_check_install(linked)
        self.assertEqual(paths["hook"].resolve(), self.hook.resolve())
        self.assertFalse((linked / ".leftblock.yml").exists())

    def test_cli_requires_both_flags_and_uses_no_signing_secret(self):
        for flags in (("--local",), ("--check-only",)):
            result = self.cli("install", *flags)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.hook.exists())
        result = self.cli("install", "--local", "--check-only", "--gitleaks", GITLEAKS or "/usr/bin/true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.hook.exists())
        self.assertFalse((self.repo / ".leftblock.yml").exists())
        self.assertFalse(Path(self.env["LEFTBLOCK_SECRET_PATH"]).exists())

    @unittest.skipUnless(GITLEAKS, "Existing Gitleaks executable required")
    def test_clean_commit_passes_and_sensitive_commit_is_blocked_before_history(self):
        self.install()
        (self.repo / "fixture.txt").write_text("safe synthetic fixture\n")
        self.git("add", "fixture.txt")
        clean = self.git("commit", "-m", "test: clean fixture", check=False)
        self.assertEqual(clean.returncode, 0, clean.stderr)
        head = self.git("rev-parse", "HEAD").stdout
        rng = random.Random(731)
        synthetic = "sk-" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(32))
        (self.repo / "fixture.txt").write_text("api_key = " + synthetic + "\n")
        self.git("add", "fixture.txt")
        blocked = self.git("commit", "-m", "test: synthetic sensitive fixture", check=False)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout, head)
        self.assertNotIn(synthetic, blocked.stdout + blocked.stderr)
        self.assertIn("leftblock-openai-key", blocked.stderr)
        self.assertFalse(Path(self.env["LEFTBLOCK_SECRET_PATH"]).exists())

    def test_explicit_config_missing_fails_closed_without_root_fallback(self):
        (self.repo / ".leftblock.yml").write_text(
            "version: 1\ncheckers:\n  - type: command\n    command: /usr/bin/true\n"
        )
        for config in (str(Path(self.temp.name) / "missing-policy"), ""):
            with self.subTest(config=config):
                result = self.cli("check", "--config", config)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
