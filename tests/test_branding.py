"""Checks for the LeftBlock namespace and independent distribution ownership."""

import argparse
import base64
import configparser
import csv
import hashlib
import io
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

from leftblock import cli
from leftblock.core import compute_hmac


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILD_TOOLS_AVAILABLE = (
    importlib.util.find_spec("setuptools") is not None
    and importlib.util.find_spec("wheel") is not None
)


class BrandingTests(unittest.TestCase):
    def test_entry_point_dispatches_each_command(self):
        commands = (
            ("install", [], "cmd_install"),
            ("check", [], "cmd_check"),
            ("hook", ["message.txt"], "cmd_hook"),
            ("verify", ["HEAD"], "cmd_verify"),
            ("approve", ["HEAD~1..HEAD"], "cmd_approve"),
        )
        for command, arguments, handler in commands:
            with self.subTest(command=command):
                with mock.patch.object(cli, handler) as invoked, \
                        mock.patch.object(sys, "argv", ["leftblock", command, *arguments]):
                    cli.main()
                invoked.assert_called_once()
                self.assertEqual(invoked.call_args.args[0].command, command)

    def test_module_displays_help_for_all_public_commands(self):
        env = dict(os.environ, PYTHONPATH=str(PROJECT_ROOT))
        for arguments in ([], ["install"], ["check"], ["hook"], ["verify"], ["approve"]):
            with self.subTest(command=arguments):
                result = subprocess.run(
                    [sys.executable, "-m", "leftblock.cli", *arguments, "--help"],
                    cwd=PROJECT_ROOT, env=env, text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0, "Module help failed")
                self.assertIn("usage:", result.stdout)
                if not arguments:
                    self.assertIn("LeftBlock", result.stdout)
                    for command in ("install", "check", "hook", "verify", "approve"):
                        self.assertIn(command, result.stdout)
                elif arguments == ["check"]:
                    self.assertIn(".leftblock.yml", result.stdout)

    def test_default_policy_check_does_not_create_signing_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            env = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith(("GIT_", "GITLEAKS_", "LEFTBLOCK_"))
            }
            env.update({
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "PYTHONPATH": str(PROJECT_ROOT),
                "LEFTBLOCK_SECRET_PATH": str(repo / "absent-signing-secret"),
            })
            init = subprocess.run(["git", "init"], cwd=repo, env=env, capture_output=True)
            self.assertEqual(init.returncode, 0, "Disposable repository setup failed")
            policy = repo / ".leftblock.yml"
            policy.write_text(
                "version: 1\ncheckers:\n"
                "  - name: synthetic-clean\n"
                "    type: command\n"
                "    command: 'true'\n"
            )
            before = policy.read_bytes()
            result = subprocess.run(
                [sys.executable, "-m", "leftblock.cli", "check"],
                cwd=repo, env=env, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, "LeftBlock rejected the default policy")
            self.assertFalse((repo / "absent-signing-secret").exists())
            self.assertEqual(policy.read_bytes(), before)
            self.assertFalse((repo / ".leftblock").exists())

    def test_modules_resolve_to_the_single_implementation_package(self):
        from leftblock import core, hooks
        for module in (cli, core, hooks):
            self.assertEqual(Path(module.__file__).resolve().parent, PROJECT_ROOT / "leftblock")
            self.assertEqual(module.__package__, "leftblock")


class ReceiptNamespaceTests(unittest.TestCase):
    """Stored validator names are authenticated data, not a brand allowlist."""

    def verify_receipt(self, signed_validator, stored_validator):
        tree = "a" * 40
        commit = "b" * 40
        timestamp = "2026-01-01T00:00:00Z"
        secret = "synthetic-receipt-test-key"
        signature = compute_hmac(tree, signed_validator, "clean", timestamp, secret)
        receipt = (
            "Synthetic fixture\n\n"
            f"Inspected-by: {stored_validator}\n"
            f"Inspection-tree: {tree}\n"
            "Inspection-result: clean\n"
            f"Inspection-at: {timestamp}\n"
            f"Inspection-sig: hmac-sha256:{signature}\n"
        )

        def git_result(command):
            if command == ["git", "rev-parse", "HEAD"]:
                output = commit
            elif command == ["git", "log", "-1", commit, "--format=%B"]:
                output = receipt
            elif command == ["git", "log", "-1", commit, "--format=%s"]:
                output = "Synthetic fixture"
            else:
                self.fail(f"Unexpected Git command: {command}")
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

        with mock.patch.object(cli, "get_secret", return_value=secret), \
                mock.patch.object(cli, "get_commit_tree_hash", return_value=tree), \
                mock.patch.object(cli, "run_cmd", side_effect=git_result), \
                mock.patch("sys.stdout", new_callable=io.StringIO), \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            cli.cmd_verify(argparse.Namespace(range="HEAD"))

    def test_historical_and_current_validator_names_verify_unchanged(self):
        for validator in ("historical-inspector-v0", "leftblock-v1"):
            with self.subTest(validator=validator):
                self.verify_receipt(validator, validator)

    def test_renaming_a_stored_validator_invalidates_the_receipt(self):
        with self.assertRaises(SystemExit) as raised:
            self.verify_receipt("historical-inspector-v0", "leftblock-v1")
        self.assertEqual(raised.exception.code, 1)


@unittest.skipUnless(BUILD_TOOLS_AVAILABLE, "Offline wheel inspection needs existing setuptools and wheel")
class DistributionOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        source = Path(cls.temporary.name) / "source"
        source.mkdir()
        for name in ("pyproject.toml", "README.md", "LICENSE"):
            shutil.copyfile(PROJECT_ROOT / name, source / name)
        shutil.copytree(
            PROJECT_ROOT / "leftblock", source / "leftblock",
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
            raise AssertionError("Expected one LeftBlock wheel")
        cls.wheel = wheels[0]
        with zipfile.ZipFile(cls.wheel) as artifact:
            cls.names = artifact.namelist()
            metadata = next(name for name in cls.names if name.endswith(".dist-info/METADATA"))
            scripts = next(name for name in cls.names if name.endswith(".dist-info/entry_points.txt"))
            cls.metadata = artifact.read(metadata).decode()
            cls.entry_points = configparser.ConfigParser()
            cls.entry_points.read_string(artifact.read(scripts).decode())
            cls.rules = artifact.read("leftblock/data/gitleaks.toml")
            cls.license = artifact.read(next(
                name for name in cls.names
                if ".dist-info/" in name and name.endswith("/LICENSE")
            ))

    def test_distribution_owns_only_leftblock_command(self):
        self.assertIn("\nName: leftblock\n", "\n" + self.metadata)
        self.assertIn("\nVersion: 0.3.3\n", "\n" + self.metadata)
        self.assertIn("\nLicense-File: LICENSE\n", "\n" + self.metadata)
        self.assertEqual(dict(self.entry_points["console_scripts"]), {"leftblock": "leftblock.cli:main"})

    def test_wheel_contains_only_implementation_and_distribution_metadata(self):
        for name in (
            "leftblock/__init__.py", "leftblock/cli.py", "leftblock/core.py",
            "leftblock/hooks.py", "leftblock/merge.py", "leftblock/data/gitleaks.toml",
        ):
            self.assertIn(name, self.names)
        self.assertEqual(
            {name.split("/")[0] for name in self.names},
            {"leftblock", "leftblock-0.3.3.dist-info"},
        )
        self.assertEqual(self.rules, (PROJECT_ROOT / "leftblock/data/gitleaks.toml").read_bytes())
        self.assertEqual(self.license, (PROJECT_ROOT / "LICENSE").read_bytes())

    @unittest.skipUnless(importlib.util.find_spec("pip"), "Offline lifecycle test requires existing pip")
    def test_upgrade_and_uninstall_preserve_independent_packages(self):
        # Generated fixtures exercise pip ownership without downloads. The
        # companion is an independent package, not an alias shipped by us.
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

            def companion_snapshot():
                return {
                    str(path.relative_to(runtime)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in runtime.rglob("*")
                    if path.is_file() and "__pycache__" not in path.parts
                    and any(part == "companion_fixture" or part.startswith("companion_fixture-")
                            for part in path.relative_to(runtime).parts)
                }

            companion = synthetic_wheel(root, "companion_fixture", "0.2.0", "independent fixture")
            previous = synthetic_wheel(root, "leftblock", "0.2.99", "prior LeftBlock fixture")
            pip("install", "--no-index", "--no-deps", str(companion), str(previous))
            self.assertIn("independent fixture", command("companion_fixture"))
            self.assertIn("prior LeftBlock fixture", command("leftblock"))
            before = companion_snapshot()
            self.assertTrue(before)
            pip("install", "--no-index", "--no-deps", "--upgrade", str(self.wheel))
            self.assertIn("LeftBlock", command("leftblock"))
            self.assertEqual(companion_snapshot(), before)
            pip("install", "--no-index", "--no-deps", "--force-reinstall", str(self.wheel))
            self.assertEqual(companion_snapshot(), before)
            pip("uninstall", "--yes", "leftblock")
            self.assertFalse((runtime / "bin" / "leftblock").exists())
            self.assertIn("independent fixture", command("companion_fixture"))
            self.assertEqual(companion_snapshot(), before)
            pip("install", "--no-index", "--no-deps", str(self.wheel))
            pip("uninstall", "--yes", "companion_fixture")
            self.assertFalse((runtime / "bin" / "companion_fixture").exists())
            self.assertIn("LeftBlock", command("leftblock"))


def synthetic_wheel(directory, name, version, marker):
    """Make a tiny deterministic independent distribution for ownership tests."""
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
