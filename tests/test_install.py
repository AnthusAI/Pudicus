import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def git(args, cwd):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, text=True, capture_output=True
    )


class InstallHookTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp_dir.name) / "repo"
        self.repo.mkdir()
        git(["init"], self.repo)
        git(["config", "user.email", "test@example.com"], self.repo)
        git(["config", "user.name", "Test User"], self.repo)

    def tearDown(self):
        self.temp_dir.cleanup()

    def install(self, cwd):
        secret_path = Path(self.temp_dir.name) / "secret"
        env = os.environ.copy()
        env.update({
            "PUDICUS_SECRET_PATH": str(secret_path),
            "PYTHONPATH": str(PROJECT_ROOT),
            "PATH": "/checker-bin:/usr/bin",
        })
        return subprocess.run(
            [sys.executable, "-m", "pudicus.cli", "install"],
            cwd=cwd,
            input="y\n",
            text=True,
            capture_output=True,
            env=env,
            check=True,
        )

    def test_install_pins_python_and_preserves_install_path(self):
        self.install(self.repo)

        hook = (self.repo / ".git" / "hooks" / "commit-msg").read_text()
        self.assertIn(f"exec {shlex.quote(sys.executable)} -m pudicus.cli hook", hook)
        self.assertIn("export PATH=/checker-bin:/usr/bin:${PATH:-}", hook)

    def test_install_from_linked_worktree_uses_shared_hooks_directory(self):
        git(["commit", "--allow-empty", "-m", "initial"], self.repo)
        worktree = Path(self.temp_dir.name) / "worktree"
        git(["worktree", "add", "-b", "worktree-branch", str(worktree)], self.repo)

        self.install(worktree)

        shared_hook = self.repo / ".git" / "hooks" / "commit-msg"
        self.assertTrue(shared_hook.is_file())
        self.assertFalse((worktree / ".git" / "hooks" / "commit-msg").exists())
        self.assertIn(
            f"exec {shlex.quote(sys.executable)} -m pudicus.cli hook",
            shared_hook.read_text(),
        )
