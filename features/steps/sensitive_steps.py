"""Steps for the zero-config sensitive-data detection feature.

All fixture values are synthesized at test time from a seeded RNG; the
test sources deliberately assemble trigger strings so the shipped
scanner stays clean when pointed at this repository.
"""

import os
import random
import shutil
import subprocess
import sys
import tempfile

from behave import given, then

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

HEX = "0123456789abcdef"


def _git(args, cwd):
    return subprocess.run(
        ["git", *args], cwd=cwd, text=True, capture_output=True
    )


def _gitleaks_available():
    return shutil.which("gitleaks") is not None


@given("a repository installed with pudicus defaults")
def step_impl(context):
    context.scenario_root = tempfile.mkdtemp()
    context.repo_dir = os.path.join(context.scenario_root, "repo")
    os.makedirs(context.repo_dir)

    _git(["init"], context.repo_dir)
    _git(["config", "user.email", "test@example.com"], context.repo_dir)
    _git(["config", "user.name", "Test User"], context.repo_dir)
    _git(
        ["git", "commit", "--allow-empty", "-m", "initial commit"],
        context.repo_dir,
    )

    if not _gitleaks_available():
        context.scenario.skip("gitleaks binary not installed")

    context.secret_path = os.path.join(context.scenario_root, "secret")
    context.env = os.environ.copy()
    context.env["PUDICUS_SECRET_PATH"] = context.secret_path
    context.env["PYTHONPATH"] = PROJECT_ROOT

    subprocess.run(
        [sys.executable, "-m", "pudicus.cli", "install"],
        cwd=context.repo_dir, input="y\n", text=True,
        capture_output=True, env=context.env,
    )


def _write_and_stage(context, filename, content):
    path = os.path.join(context.repo_dir, filename)
    with open(path, "w") as f:
        f.write(content)
    _git(["add", ".pudicus.yml"], context.repo_dir)
    _git(["add", ".pudicus"], context.repo_dir)
    _git(["add", filename], context.repo_dir)

    context.msg_file = os.path.join(context.repo_dir, "commit_msg.txt")
    with open(context.msg_file, "w") as f:
        f.write("test: staged content\n")


@given("a staged file containing a synthetic OpenAI-style key")
def step_impl(context):
    rng = random.Random(42)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    key = "sk-" + "".join(rng.choice(alphabet) for _ in range(48))
    _write_and_stage(context, "keys_api.txt", "OPENAI_API_KEY=%s\n" % key)


@given("a staged file containing harmless source code")
def step_impl(context):
    content = "\n".join([
        "def greet(name):",
        '    return "hello, " + name',
        "",
        "print(greet('world'))",
    ]) + "\n"
    _write_and_stage(context, "app.py", content)


@given("a staged file containing public wallet addresses and digests")
def step_impl(context):
    rng = random.Random(42)
    eth_address = "0x" + "".join(rng.choice(HEX) for _ in range(40))
    digest = "".join(rng.choice(HEX) for _ in range(64))
    content = "\n".join([
        "eth deposit address: " + eth_address,
        "sha256 digest: " + digest,
    ]) + "\n"
    _write_and_stage(context, "addresses.txt", content)


@when("I commit the staged files")
def step_impl(context):
    context.result = _git(
        ["commit", "-F", context.msg_file], context.repo_dir
    )


@then("the committed message should contain a clean inspection result")
def step_impl(context):
    msg = _git(["log", "-1", "--format=%B"], context.repo_dir).stdout
    assert "Inspection-result: clean" in msg, msg


def after_scenario(context, scenario):
    if hasattr(context, "scenario_root") and os.path.exists(
        context.scenario_root
    ):
        shutil.rmtree(context.scenario_root, ignore_errors=True)