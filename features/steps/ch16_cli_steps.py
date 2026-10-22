"""Steps for chapter 16 (the command line).

Covers the installed ``leftblock`` command, receipt validator names, and the
packaging promises (what the distribution installs, and that upgrading or
removing it leaves other packages alone). Packaging scenarios build a wheel
and a throwaway environment offline: no network is used, and they are skipped
when setuptools, wheel or pip are unavailable.
"""

import atexit
import base64
import csv
import configparser
import hashlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import venv
import zipfile

from behave import given, then, when

import world
from leftblock.core import compute_hmac

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RECEIPT_TIMESTAMP = "2026-01-01T00:00:00Z"

_BUILT = {}
_CLEANUP = []


def _project_version():
    with open(os.path.join(PROJECT_ROOT, "pyproject.toml")) as handle:
        return re.search(r'^version = "([^"]+)"', handle.read(), re.MULTILINE).group(1)


def _scratch():
    path = tempfile.mkdtemp(prefix="leftblock-wheel-")
    _CLEANUP.append(path)
    return path


atexit.register(lambda: [shutil.rmtree(p, ignore_errors=True) for p in _CLEANUP])


# --- The installed command ---------------------------------------------------

@when('I run the installed leftblock command with "{args}"')
def step_run_installed(context, args):
    """Run the ``leftblock`` console script installed next to this interpreter."""
    command = os.path.join(os.path.dirname(sys.executable), "leftblock")
    assert os.path.exists(command), "the leftblock command is not installed"
    context.result = world.run(context, [command, *args.split()])


@when("I run leftblock without any command")
def step_run_bare(context):
    """Run the program with no arguments at all."""
    context.result = world.leftblock(context)


@then("stdout reports a leftblock version number")
def step_version_number(context):
    """stdout is ``leftblock`` followed by a dotted version."""
    assert re.fullmatch(r"leftblock \d+\.\d+\.\d+\S*", context.result.stdout.strip()), \
        context.result.stdout


# --- Policy checks that must not create credentials ------------------------

@given("a record of the policy file and the signing secret location")
def step_record_policy(context):
    """Remember the root policy's bytes; the secret must stay absent."""
    with open(os.path.join(context.repo, ".leftblock.yml"), "rb") as handle:
        context.policy_bytes = handle.read()
    assert not os.path.exists(context.secret_path)


@then("the policy file is exactly as it was")
def step_policy_intact(context):
    """The root policy file was not rewritten."""
    with open(os.path.join(context.repo, ".leftblock.yml"), "rb") as handle:
        assert handle.read() == context.policy_bytes


@then("no signing credentials were created")
def step_no_credentials(context):
    """No secret file and no .leftblock directory exist."""
    assert not os.path.exists(context.secret_path), "a secret was created"
    assert not os.path.exists(os.path.join(context.repo, ".leftblock"))


# --- Receipts and validator names -------------------------------------------

@given('a commit whose receipt names the validator "{stored}" and was signed for "{signed}"')
def step_signed_commit(context, stored, signed):
    """A commit carrying a receipt for its own tree.

    The signature is made with the account secret for the ``signed`` name,
    while the receipt text records ``stored`` as the validator.
    """
    world.write_file(context, "receipt.txt", "receipt fixture\n")
    world.git(context, "add", "receipt.txt")
    tree = world.git(context, "write-tree").stdout.strip()
    with open(context.secret_path) as handle:
        secret = handle.read().strip()
    signature = compute_hmac(tree, signed, "clean", RECEIPT_TIMESTAMP, secret)
    message = (
        "test: receipt fixture\n\n"
        "Inspected-by: %s\nInspection-tree: %s\nInspection-result: clean\n"
        "Inspection-at: %s\nInspection-sig: hmac-sha256:%s\n"
        % (stored, tree, RECEIPT_TIMESTAMP, signature)
    )
    world.git(context, "commit", "-q", "--no-verify", "-m", message)


# --- The distribution -------------------------------------------------------

def _need_build_tools(context):
    for module in ("setuptools", "wheel"):
        if importlib.util.find_spec(module) is None:
            context.scenario.skip("%s is not installed; the wheel cannot be built offline" % module)
            return False
    return True


def _build_wheel():
    if "wheel" in _BUILT:
        return _BUILT["wheel"]
    base = _scratch()
    source, output = os.path.join(base, "source"), os.path.join(base, "wheel")
    os.makedirs(source)
    os.makedirs(output)
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copyfile(os.path.join(PROJECT_ROOT, name), os.path.join(source, name))
    shutil.copytree(
        os.path.join(PROJECT_ROOT, "leftblock"), os.path.join(source, "leftblock"),
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    proc = subprocess.run(
        [sys.executable, "-c",
         "from setuptools.build_meta import build_wheel; import sys; build_wheel(sys.argv[1])",
         output],
        cwd=source, text=True, capture_output=True,
    )
    assert proc.returncode == 0, "offline wheel build failed:\n" + proc.stderr[-2000:]
    wheels = [n for n in os.listdir(output) if n.endswith(".whl")]
    assert len(wheels) == 1, wheels
    _BUILT["wheel"] = os.path.join(output, wheels[0])
    return _BUILT["wheel"]


def _wheel_contents():
    if "contents" not in _BUILT:
        with zipfile.ZipFile(_build_wheel()) as artifact:
            names = artifact.namelist()
            meta = next(n for n in names if n.endswith(".dist-info/METADATA"))
            scripts = next(n for n in names if n.endswith(".dist-info/entry_points.txt"))
            entry = configparser.ConfigParser()
            entry.read_string(artifact.read(scripts).decode())
            _BUILT["contents"] = {
                "names": names,
                "metadata": artifact.read(meta).decode(),
                "entry_points": entry,
                "rules": artifact.read("leftblock/data/gitleaks.toml"),
                "license": artifact.read(next(
                    n for n in names if ".dist-info/" in n and n.endswith("/LICENSE")
                )),
            }
    return _BUILT["contents"]


@given("a wheel built offline from the project sources")
def step_build_wheel(context):
    """Build the distribution wheel from a copy of the sources, without a network."""
    if _need_build_tools(context):
        context.wheel = _build_wheel()


@then("the distribution is named leftblock at the project's version, with its license")
def step_wheel_metadata(context):
    """The wheel metadata carries the distribution name, version and license file."""
    metadata = "\n" + _wheel_contents()["metadata"]
    assert "\nName: leftblock\n" in metadata
    assert "\nVersion: %s\n" % _project_version() in metadata
    assert "\nLicense-File: LICENSE\n" in metadata


@then('the distribution installs one command, "leftblock", running "leftblock.cli:main"')
def step_wheel_command(context):
    """The only console script is ``leftblock``."""
    scripts = dict(_wheel_contents()["entry_points"]["console_scripts"])
    assert scripts == {"leftblock": "leftblock.cli:main"}, scripts


@then("the distribution contains the implementation modules and the shipped rules")
def step_wheel_modules(context):
    """Every implementation module and the rules file are in the wheel."""
    names = _wheel_contents()["names"]
    for name in (
        "leftblock/__init__.py", "leftblock/cli.py", "leftblock/core.py",
        "leftblock/hooks.py", "leftblock/merge.py", "leftblock/data/gitleaks.toml",
    ):
        assert name in names, name


@then("the distribution contains only the leftblock package and its own metadata")
def step_wheel_only(context):
    """Nothing but ``leftblock/`` and its dist-info is installed."""
    tops = {name.split("/")[0] for name in _wheel_contents()["names"]}
    assert tops == {"leftblock", "leftblock-%s.dist-info" % _project_version()}, tops


@then("the bundled rules and license are identical to the project's")
def step_wheel_identical(context):
    """The rules and the license inside the wheel match the sources byte for byte."""
    contents = _wheel_contents()
    with open(os.path.join(PROJECT_ROOT, "leftblock/data/gitleaks.toml"), "rb") as handle:
        assert contents["rules"] == handle.read()
    with open(os.path.join(PROJECT_ROOT, "LICENSE"), "rb") as handle:
        assert contents["license"] == handle.read()


# --- Upgrading and uninstalling beside other packages ------------------------

def _synthetic_wheel(directory, name, version, marker):
    """A tiny deterministic distribution with one console command."""
    info = "%s-%s.dist-info" % (name, version)
    files = {
        "%s/__init__.py" % name: b"",
        "%s/cli.py" % name: ("def main():\n    print(%r)\n" % marker).encode(),
        info + "/METADATA": ("Metadata-Version: 2.1\nName: %s\nVersion: %s\n" % (name, version)).encode(),
        info + "/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        info + "/entry_points.txt": ("[console_scripts]\n%s = %s.cli:main\n" % (name, name)).encode(),
    }
    record = io.StringIO()
    writer = csv.writer(record)
    for path, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow((path, "sha256=" + digest, len(data)))
    writer.writerow((info + "/RECORD", "", ""))
    files[info + "/RECORD"] = record.getvalue().encode()
    wheel = os.path.join(directory, "%s-%s-py3-none-any.whl" % (name, version))
    with zipfile.ZipFile(wheel, "w") as artifact:
        for path, data in files.items():
            artifact.writestr(path, data)
    return wheel


def _pip(context, *args):
    env = {k: v for k, v in context.env.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "--python", context.python, "--isolated",
         "--disable-pip-version-check", "--no-input", *args],
        cwd=context.root, env=env, text=True, capture_output=True,
    )
    assert proc.returncode == 0, "offline pip step failed:\n" + proc.stderr[-2000:]


def _companion_snapshot(context):
    snapshot = {}
    for current, _, files in os.walk(context.runtime):
        for name in files:
            path = os.path.join(current, name)
            rel = os.path.relpath(path, context.runtime)
            parts = rel.split(os.sep)
            if "__pycache__" in parts:
                continue
            if any(p == "companion_fixture" or p.startswith("companion_fixture-") for p in parts):
                with open(path, "rb") as handle:
                    snapshot[rel] = hashlib.sha256(handle.read()).hexdigest()
    return snapshot


def _run_command(context, name):
    proc = subprocess.run(
        [os.path.join(context.runtime, "bin", name), "--help"], cwd=context.root,
        env={k: v for k, v in context.env.items() if k not in ("PYTHONPATH", "PYTHONHOME")},
        text=True, capture_output=True,
    )
    return proc


@given("an isolated environment holding an independent package and an older LeftBlock")
def step_pip_environment(context):
    """Install, offline, a companion package and a previous LeftBlock release."""
    if importlib.util.find_spec("pip") is None or not _need_build_tools(context):
        context.scenario.skip("pip, setuptools and wheel are required for offline installs")
        return
    context.wheel = _build_wheel()
    context.runtime = os.path.join(context.root, "pip-runtime")
    venv.EnvBuilder(with_pip=False, system_site_packages=True).create(context.runtime)
    context.python = os.path.join(context.runtime, "bin", "python")
    # LeftBlock is installed without dependencies (offline); give it PyYAML.
    import yaml
    packages = next(
        os.path.join(context.runtime, "lib", d, "site-packages")
        for d in os.listdir(os.path.join(context.runtime, "lib"))
    )
    shutil.copytree(os.path.dirname(yaml.__file__), os.path.join(packages, "yaml"),
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    companion = _synthetic_wheel(context.root, "companion_fixture", "0.2.0", "independent fixture")
    previous = _synthetic_wheel(context.root, "leftblock", "0.2.99", "prior LeftBlock fixture")
    _pip(context, "install", "--no-index", "--no-deps", companion, previous)
    assert "independent fixture" in _run_command(context, "companion_fixture").stdout
    assert "prior LeftBlock fixture" in _run_command(context, "leftblock").stdout
    context.companion_before = _companion_snapshot(context)
    assert context.companion_before


@when("I upgrade LeftBlock from the built wheel")
def step_upgrade(context):
    """``pip install --upgrade`` of the built wheel."""
    _pip(context, "install", "--no-index", "--no-deps", "--upgrade", context.wheel)


@when("I force-reinstall LeftBlock from the built wheel")
def step_force_reinstall(context):
    """``pip install --force-reinstall`` of the built wheel."""
    _pip(context, "install", "--no-index", "--no-deps", "--force-reinstall", context.wheel)


@when("I uninstall LeftBlock")
def step_uninstall(context):
    """``pip uninstall leftblock``."""
    _pip(context, "uninstall", "--yes", "leftblock")


@when("I uninstall the independent package")
def step_uninstall_companion(context):
    """``pip uninstall companion_fixture``."""
    _pip(context, "uninstall", "--yes", "companion_fixture")


@when("I install LeftBlock from the built wheel")
def step_install_wheel(context):
    """A plain ``pip install`` of the built wheel."""
    _pip(context, "install", "--no-index", "--no-deps", context.wheel)


@then("the independent package is exactly as it was")
def step_companion_intact(context):
    """Every file of the companion package has the digest it had at the start."""
    assert _companion_snapshot(context) == context.companion_before


@then("the independent package's command still works")
def step_companion_works(context):
    """The companion's console command runs."""
    proc = _run_command(context, "companion_fixture")
    assert proc.returncode == 0 and "independent fixture" in proc.stdout, proc.stderr


@then("the leftblock command is the new release")
def step_new_release(context):
    """The command now prints LeftBlock's own help."""
    proc = _run_command(context, "leftblock")
    assert proc.returncode == 0 and "pluggable inspection gate" in proc.stdout, proc.stderr


@then("the leftblock command is gone")
def step_command_gone(context):
    """No ``leftblock`` executable remains in the environment."""
    assert not os.path.exists(os.path.join(context.runtime, "bin", "leftblock"))


@then("the independent package's command is gone")
def step_companion_command_gone(context):
    """No ``companion_fixture`` executable remains in the environment."""
    assert not os.path.exists(os.path.join(context.runtime, "bin", "companion_fixture"))
