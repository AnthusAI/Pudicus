"""Compatibility checks for the LeftBlock name and the existing Pudicus API."""

import base64
import configparser
import csv
import hashlib
import io
import json
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
import venv

from leftblock import cli as leftblock_cli
from pudicus import cli as pudicus_cli


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILD_TOOLS_AVAILABLE = (
    importlib.util.find_spec("setuptools") is not None
    and importlib.util.find_spec("wheel") is not None
)


class BrandingCompatibilityTests(unittest.TestCase):
    def test_both_entry_points_share_command_dispatch(self):
        self.assertIs(leftblock_cli.main, pudicus_cli.main)
        commands = (
            ("install", [], "cmd_install"),
            ("check", [], "cmd_check"),
            ("hook", ["message.txt"], "cmd_hook"),
            ("verify", ["HEAD"], "cmd_verify"),
            ("approve", ["HEAD~1..HEAD"], "cmd_approve"),
        )
        for command_name in ("leftblock", "pudicus"):
            for command, arguments, handler in commands:
                with self.subTest(entry=command_name, command=command):
                    with mock.patch.object(pudicus_cli, handler) as invoked, \
                            mock.patch.object(sys, "argv", [command_name, command, *arguments]):
                        entry = leftblock_cli if command_name == "leftblock" else pudicus_cli
                        entry.main()
                    invoked.assert_called_once()
                    self.assertEqual(invoked.call_args.args[0].command, command)

    def test_both_module_names_can_display_help(self):
        env = dict(os.environ, PYTHONPATH=str(PROJECT_ROOT))
        for module in ("leftblock.cli", "pudicus.cli"):
            with self.subTest(module=module):
                result = subprocess.run(
                    [sys.executable, "-m", module, "--help"],
                    cwd=PROJECT_ROOT, env=env, text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0, "Module help failed")
                self.assertIn("LeftBlock (formerly Pudicus)", result.stdout)
                self.assertIn("check", result.stdout)
                self.assertIn("verify", result.stdout)

    def test_new_module_reads_legacy_policy_without_new_signing_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            env = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith(("GIT_", "GITLEAKS_", "PUDICUS_"))
            }
            env.update({
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "PYTHONPATH": str(PROJECT_ROOT),
                "PUDICUS_SECRET_PATH": str(repo / "absent-signing-secret"),
            })
            init = subprocess.run(["git", "init"], cwd=repo, env=env, capture_output=True)
            self.assertEqual(init.returncode, 0, "Disposable repository setup failed")
            (repo / ".pudicus.yml").write_text(
                "version: 1\ncheckers:\n"
                "  - name: synthetic-clean\n"
                "    type: command\n"
                "    command: 'true'\n"
            )
            result = subprocess.run(
                [sys.executable, "-m", "leftblock.cli", "check"],
                cwd=repo, env=env, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, "LeftBlock rejected the legacy policy")
            self.assertFalse((repo / "absent-signing-secret").exists())
            self.assertFalse((repo / ".leftblock.yml").exists())
            self.assertTrue((repo / ".pudicus.yml").exists())

    def test_legacy_editable_loader_resolves_adjacent_source_without_sys_path_changes(self):
        code = """
import importlib.util, pathlib, sys
package = pathlib.Path(sys.argv[1]) / 'pudicus'
before = list(sys.path)
spec = importlib.util.spec_from_file_location('pudicus', package / '__init__.py', submodule_search_locations=[str(package)])
module = importlib.util.module_from_spec(spec)
sys.modules['pudicus'] = module
spec.loader.exec_module(module)
from pudicus import cli, core, hooks
from leftblock import cli as new_cli, core as new_core, hooks as new_hooks
assert cli is new_cli and core is new_core and hooks is new_hooks
assert sys.path == before
assert pathlib.Path(new_cli.__file__).resolve() == package.parent / 'leftblock' / 'cli.py'
"""
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-c", code, str(PROJECT_ROOT)],
                cwd=temporary, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, "Legacy editable import fallback failed")


@unittest.skipUnless(BUILD_TOOLS_AVAILABLE, "Offline wheel inspection needs existing setuptools and wheel")
class DistributionCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        source = Path(cls.temporary.name) / "source"
        source.mkdir()
        for name in ("pyproject.toml", "README.md", "LICENSE"):
            shutil.copyfile(PROJECT_ROOT / name, source / name)
        for package in ("pudicus", "leftblock"):
            shutil.copytree(
                PROJECT_ROOT / package, source / package,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
        output = Path(cls.temporary.name) / "wheel"
        output.mkdir()
        result = subprocess.run(
            [
                sys.executable, "-c",
                "from setuptools.build_meta import build_wheel; "
                "import sys; build_wheel(sys.argv[1])",
                str(output),
            ],
            cwd=source, text=True, capture_output=True,
        )
        if result.returncode:
            raise AssertionError("Offline wheel build failed; no dependency installation was attempted")
        wheels = list(output.glob("*.whl"))
        if len(wheels) != 1:
            raise AssertionError("Expected one compatibility wheel")
        with zipfile.ZipFile(wheels[0]) as artifact:
            cls.wheel = wheels[0]
            cls.names = artifact.namelist()
            metadata = next(name for name in cls.names if name.endswith(".dist-info/METADATA"))
            scripts = next(name for name in cls.names if name.endswith(".dist-info/entry_points.txt"))
            cls.metadata = artifact.read(metadata).decode()
            cls.entry_points = configparser.ConfigParser()
            cls.entry_points.read_string(artifact.read(scripts).decode())

    def test_new_distribution_owns_only_new_command(self):
        self.assertIn("\nName: leftblock\n", "\n" + self.metadata)
        self.assertIn("\nVersion: 0.3.0\n", "\n" + self.metadata)
        self.assertIn("\nLicense-File: LICENSE\n", "\n" + self.metadata)
        self.assertEqual(dict(self.entry_points["console_scripts"]), {"leftblock": "leftblock.cli:main"})

    def test_wheel_contains_implementation_and_rules_without_legacy_files(self):
        for name in (
            "leftblock/__init__.py", "leftblock/cli.py", "leftblock/core.py",
            "leftblock/hooks.py", "leftblock/data/gitleaks.toml",
            "leftblock-0.3.0.dist-info/LICENSE",
        ):
            self.assertIn(name, self.names)
        self.assertFalse(any(name.startswith(("pudicus/", "pudicus-", "gitbouncer/")) for name in self.names))
        self.assertEqual(
            (PROJECT_ROOT / "leftblock/data/gitleaks.toml").read_bytes(),
            (PROJECT_ROOT / "pudicus/data/gitleaks.toml").read_bytes(),
        )

    @unittest.skipUnless(importlib.util.find_spec("pip"), "Offline lifecycle test requires existing pip")
    def test_upgrade_and_uninstall_preserve_independent_packages(self):
        # Synthetic prior releases exercise pip ownership without a network or
        # registry dependency. They are test fixtures, not published releases.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            venv.EnvBuilder(with_pip=False, system_site_packages=True).create(runtime)
            python = runtime / "bin" / "python"
            env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
            env["PYTHONDONTWRITEBYTECODE"] = "1"

            def pip(*args):
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "--python", str(python),
                     "--isolated", "--disable-pip-version-check", "--no-input", *args],
                    cwd=root, env=env, text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0, "Offline package lifecycle operation failed")

            def command(name):
                result = subprocess.run(
                    [str(runtime / "bin" / name), "--help"], cwd=root,
                    env=env, text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0, "Installed command failed")
                return result.stdout

            def old_snapshot():
                return {str(path.relative_to(runtime)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in runtime.rglob("*")
                        if path.is_file() and ("pudicus" in path.parts or path.name == "pudicus")
                        and "__pycache__" not in path.parts}

            legacy = synthetic_wheel(root, "pudicus", "0.2.0", "synthetic-legacy-pudicus")
            previous = synthetic_wheel(root, "leftblock", "0.2.99", "synthetic-prior-leftblock")
            pip("install", "--no-index", "--no-deps", str(legacy), str(previous))
            self.assertIn("synthetic-legacy-pudicus", command("pudicus"))
            before = old_snapshot()
            self.assertTrue(before)
            pip("install", "--no-index", "--no-deps", "--upgrade", str(self.wheel))
            self.assertIn("LeftBlock (formerly Pudicus)", command("leftblock"))
            self.assertEqual(old_snapshot(), before)
            pip("install", "--no-index", "--no-deps", "--force-reinstall", str(self.wheel))
            self.assertEqual(old_snapshot(), before)
            pip("uninstall", "--yes", "leftblock")
            self.assertFalse((runtime / "bin" / "leftblock").exists())
            self.assertIn("synthetic-legacy-pudicus", command("pudicus"))
            self.assertEqual(old_snapshot(), before)
            pip("install", "--no-index", "--no-deps", str(self.wheel))
            pip("uninstall", "--yes", "pudicus")
            self.assertFalse((runtime / "bin" / "pudicus").exists())
            self.assertIn("LeftBlock (formerly Pudicus)", command("leftblock"))


def synthetic_wheel(directory, name, version, marker):
    """Make a tiny deterministic legacy distribution for offline ownership tests."""
    info = f"{name}-{version}.dist-info"
    files = {
        f"{name}/__init__.py": b"",
        f"{name}/cli.py": f"def main():\n    print({marker!r})\n".encode(),
        f"{info}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode(),
        f"{info}/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{info}/entry_points.txt": f"[console_scripts]\n{name} = {name}.cli:main\n".encode(),
    }
    record = io.StringIO()
    writer = csv.writer(record)
    for path, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow((path, "sha256=" + digest, len(data)))
    writer.writerow((f"{info}/RECORD", "", ""))
    files[f"{info}/RECORD"] = record.getvalue().encode()
    wheel = directory / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as artifact:
        for path, data in files.items():
            artifact.writestr(path, data)
    return wheel


if __name__ == "__main__":
    unittest.main()
