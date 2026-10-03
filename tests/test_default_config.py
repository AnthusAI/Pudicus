"""Tests that `pudicus install` wires up the zero-config defaults:
a default .pudicus.yml and the packaged gitleaks ruleset, both
non-destructive to pre-existing files."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGED_RULESET = PROJECT_ROOT / "pudicus" / "data" / "gitleaks.toml"


def run_install(repo, answer="y\n"):
    env = os.environ.copy()
    env["PUDICUS_SECRET_PATH"] = os.path.join(repo.parent, "secret")
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    return subprocess.run(
        [sys.executable, "-m", "pudicus.cli", "install"],
        cwd=repo, input=answer, text=True, capture_output=True, env=env,
    )


class InstallDefaultConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp_dir.name) / "repo"
        self.repo.mkdir()
        for cmd in (
            ["git", "init"],
            ["git", "config", "user.email", "test@example.com"],
            ["git", "config", "user.name", "Test User"],
        ):
            subprocess.run(cmd, cwd=self.repo, check=True, capture_output=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_install_writes_default_configs(self):
        proc = run_install(self.repo)
        self.assertEqual(proc.returncode, 0, proc.stderr)

        yml = self.repo / ".pudicus.yml"
        self.assertTrue(yml.exists(), proc.stdout)
        yml_text = yml.read_text()
        self.assertIn("gitleaks protect --staged", yml_text)
        self.assertIn(".pudicus/gitleaks.toml", yml_text)
        self.assertIn("finding_codes: [1]", yml_text)

        ruleset = self.repo / ".pudicus" / "gitleaks.toml"
        self.assertTrue(ruleset.exists())
        self.assertEqual(
            ruleset.read_bytes(), PACKAGED_RULESET.read_bytes()
        )

    def test_install_preserves_existing_configs(self):
        yml = self.repo / ".pudicus.yml"
        yml.write_text("version: 1\ncheckers: []\n")
        pudicus_dir = self.repo / ".pudicus"
        pudicus_dir.mkdir()
        ruleset = pudicus_dir / "gitleaks.toml"
        ruleset.write_text("# user-customized ruleset\n")

        proc = run_install(self.repo)
        self.assertEqual(proc.returncode, 0, proc.stderr)

        self.assertEqual(yml.read_text(), "version: 1\ncheckers: []\n")
        self.assertEqual(ruleset.read_text(), "# user-customized ruleset\n")

    def test_default_config_is_usable_by_load_config(self):
        proc = run_install(self.repo)
        self.assertEqual(proc.returncode, 0, proc.stderr)

        sys.path.insert(0, str(PROJECT_ROOT))
        try:
            from pudicus.core import load_config
            config = load_config(str(self.repo))
            self.assertIn("checkers", config)
            self.assertEqual(config["checkers"][0]["name"], "gitleaks")
        finally:
            sys.path.pop(0)


if __name__ == "__main__":
    unittest.main()