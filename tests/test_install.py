import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from leftblock.hooks import STATE_NAME, install_hook, validate_hook_install


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def git(args, cwd):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, text=True, capture_output=True
    )


class InstallHookTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.repo = Path(self.temp_dir.name) / "repo"
        self.repo.mkdir()
        env = os.environ.copy()
        for key in list(env):
            if key.startswith("GIT_"):
                del env[key]
        env.update({
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "LEFTBLOCK_SECRET_PATH": str(Path(self.temp_dir.name) / "secret"),
            "PYTHONPATH": str(PROJECT_ROOT),
        })
        self.environment = patch.dict(os.environ, env, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        git(["init"], self.repo)
        git(["config", "user.email", "test@example.com"], self.repo)
        git(["config", "user.name", "Test User"], self.repo)
        self.hook_dir = self.repo / ".git" / "hooks"
        self.hook = self.hook_dir / "commit-msg"
        self.state = self.hook_dir / STATE_NAME

    def install(self, cwd):
        with patch.dict(os.environ, {"PATH": "/checker-bin:/usr/bin"}):
            return install_hook(cwd)

    def run_cli_install(self):
        return subprocess.run(
            [sys.executable, "-m", "leftblock.cli", "install"], cwd=self.repo,
            input="y\n", text=True, capture_output=True,
        )

    def test_install_pins_python_and_preserves_install_path(self):
        self.assertTrue(self.install(self.repo))
        hook = self.hook.read_text()
        self.assertIn(f"exec {shlex.quote(sys.executable)} -m leftblock.cli hook", hook)
        self.assertIn("export PATH=/checker-bin:/usr/bin:${PATH:-}", hook)
        self.assertEqual(self.hook.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        metadata = json.loads(self.state.read_text())
        self.assertEqual(metadata["sha256"], hashlib.sha256(self.hook.read_bytes()).hexdigest())

    def test_missing_leftblock_runtime_cannot_install_a_broken_hook(self):
        run = subprocess.run

        def missing_runtime(args, **kwargs):
            if args[:5] == [sys.executable, "-B", "-m", "leftblock.cli", "hook"]:
                return subprocess.CompletedProcess(args, 1, "", "module unavailable")
            return run(args, **kwargs)

        with patch("leftblock.hooks.subprocess.run", side_effect=missing_runtime):
            with self.assertRaisesRegex(ValueError, "Install LeftBlock"):
                self.install(self.repo)
        self.assertFalse(self.hook.exists())
        self.assertFalse(self.state.exists())
        self.assertFalse((self.repo / ".leftblock.yml").exists())

    def test_install_from_linked_worktree_uses_shared_hooks_directory(self):
        git(["commit", "--allow-empty", "-m", "initial"], self.repo)
        worktree = Path(self.temp_dir.name) / "worktree"
        git(["worktree", "add", "-b", "worktree-branch", str(worktree)], self.repo)
        self.install(worktree)
        self.assertTrue(self.hook.is_file())
        self.assertFalse((worktree / ".git" / "hooks" / "commit-msg").exists())
        self.assertEqual(validate_hook_install(worktree).resolve(), self.hook.resolve())

    def test_reinstall_is_idempotent_and_can_refresh_captured_path(self):
        self.install(self.repo)
        before = self.hook.read_bytes(), self.state.read_bytes(), self.hook.stat().st_mtime_ns
        self.install(self.repo)
        self.assertEqual(before, (
            self.hook.read_bytes(), self.state.read_bytes(), self.hook.stat().st_mtime_ns
        ))
        with patch.dict(os.environ, {"PATH": "/different-bin:/usr/bin"}):
            install_hook(self.repo)
        self.assertIn("export PATH=/different-bin:/usr/bin:", self.hook.read_text())
        validate_hook_install(self.repo)

    def test_existing_foreign_executable_or_disabled_hook_is_preserved(self):
        for mode in (0o755, 0o644):
            with self.subTest(mode=mode):
                content = "#!/bin/sh\n# owner hook\nexit 7\n"
                self.hook.write_text(content)
                self.hook.chmod(mode)
                with self.assertRaisesRegex(ValueError, "unmanaged"):
                    self.install(self.repo)
                self.assertEqual(self.hook.read_text(), content)
                self.assertEqual(self.hook.stat().st_mode & 0o777, mode)
                self.assertFalse(self.state.exists())

    def test_edited_managed_hook_and_disabled_managed_hook_are_preserved(self):
        self.install(self.repo)
        original = self.hook.read_bytes()
        self.hook.write_bytes(original + b"# owner addition\n")
        with self.assertRaisesRegex(ValueError, "changed"):
            self.install(self.repo)
        self.assertEqual(self.hook.read_bytes(), original + b"# owner addition\n")
        self.hook.write_bytes(original)
        self.hook.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "disabled"):
            self.install(self.repo)
        self.assertEqual(self.hook.stat().st_mode & 0o777, 0o644)

    def test_custom_hooks_path_refuses_before_creating_files(self):
        for configured in (".husky/_", str(Path(self.temp_dir.name) / "shared-hooks"), ""):
            with self.subTest(configured=configured):
                git(["config", "core.hooksPath", configured], self.repo)
                before = sorted(str(p.relative_to(self.repo)) for p in self.repo.rglob("*"))
                with self.assertRaisesRegex(ValueError, "core.hooksPath"):
                    self.install(self.repo)
                after = sorted(str(p.relative_to(self.repo)) for p in self.repo.rglob("*"))
                self.assertEqual(before, after)
                self.assertFalse(self.hook.exists())
                self.assertFalse(self.state.exists())

    def test_global_hooks_path_refuses_without_changing_config(self):
        global_config = Path(self.temp_dir.name) / "global.gitconfig"
        global_config.write_text('[core]\n\thooksPath = shared-hooks\n')
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(global_config)}):
            before = global_config.read_bytes()
            with self.assertRaisesRegex(ValueError, "core.hooksPath"):
                self.install(self.repo)
            self.assertEqual(global_config.read_bytes(), before)
        self.assertFalse(self.hook.exists())

    def test_symlink_hook_and_state_are_preserved(self):
        target = Path(self.temp_dir.name) / "owner-file"
        target.write_text("owner content\n")
        for path in (self.hook, self.state):
            with self.subTest(path=path.name):
                path.symlink_to(target)
                with self.assertRaisesRegex(ValueError, "regular file"):
                    self.install(self.repo)
                self.assertTrue(path.is_symlink())
                self.assertEqual(target.read_text(), "owner content\n")
                path.unlink()

    def test_symlink_hooks_directory_is_preserved(self):
        original = self.hook_dir.with_name("original-hooks")
        self.hook_dir.rename(original)
        self.hook_dir.symlink_to(original, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "regular directory"):
            self.install(self.repo)
        self.assertTrue(self.hook_dir.is_symlink())
        self.assertFalse((original / "commit-msg").exists())

    def test_nonregular_hook_and_malformed_state_are_preserved(self):
        self.hook.mkdir()
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.install(self.repo)
        self.assertTrue(self.hook.is_dir())
        self.hook.rmdir()
        self.install(self.repo)
        for content in ("[]", "{invalid", '{"version": 1}'):
            self.state.write_text(content)
            before = self.hook.read_bytes()
            with self.assertRaises(ValueError):
                self.install(self.repo)
            self.assertEqual(self.hook.read_bytes(), before)
            self.assertEqual(self.state.read_text(), content)

    def test_installed_hook_runs_with_minimal_runtime_path(self):
        self.install(self.repo)
        # Use a tiny local command checker; no secrets or real source are read.
        (self.repo / ".leftblock.yml").write_text(
            "version: 1\ncheckers:\n  - name: synthetic\n    type: command\n"
            "    command: /usr/bin/true\n    success_codes: [0]\n"
        )
        Path(os.environ["LEFTBLOCK_SECRET_PATH"]).write_text("synthetic-test-secret")
        message = self.repo / "message.txt"
        message.write_text("test: synthetic\n")
        with patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}):
            result = subprocess.run(
                [str(self.hook), str(message)], cwd=self.repo,
                text=True, capture_output=True
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Inspection-result: clean", message.read_text())

    def test_cli_install_success(self):
        result = self.run_cli_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.hook.is_file())
        self.assertTrue(self.state.is_file())
        self.assertTrue((self.repo / ".leftblock.yml").is_file())
        self.assertTrue(Path(os.environ["LEFTBLOCK_SECRET_PATH"]).is_file())

    def test_cli_refuses_foreign_hook_even_with_yes_on_stdin(self):
        self.hook.write_text("#!/bin/sh\nexit 7\n")
        before = self.hook.read_bytes()
        result = self.run_cli_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.hook.read_bytes(), before)
        self.assertFalse(self.state.exists())
        self.assertFalse((self.repo / ".leftblock.yml").exists())
        self.assertFalse(Path(os.environ["LEFTBLOCK_SECRET_PATH"]).exists())

    def test_cli_refuses_hook_manager_without_writing_defaults(self):
        git(["config", "core.hooksPath", ".husky/_"], self.repo)
        result = self.run_cli_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("core.hooksPath", result.stderr)
        self.assertFalse(self.hook.exists())
        self.assertFalse((self.repo / ".leftblock.yml").exists())
        self.assertFalse(Path(os.environ["LEFTBLOCK_SECRET_PATH"]).exists())


if __name__ == "__main__":
    unittest.main()
