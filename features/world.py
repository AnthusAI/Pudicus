"""Helpers for the step modules (not steps themselves).

Lives outside features/steps/ so behave loads it exactly once; step modules
do ``import world``. All functions take the behave ``context``.
"""

import os
import random
import shutil
import subprocess
import sys
from types import SimpleNamespace

import synthetic_data

TIMEOUT = 180
COMMIT_MESSAGE = "test: staged content"


def run(context, argv, cwd=None, stdin=None):
    """Run ``argv`` with the scenario environment; never raises on failure."""
    proc = subprocess.run(
        argv, cwd=cwd or context.repo or context.root, env=context.env,
        text=True, capture_output=True, timeout=TIMEOUT,
        stdin=subprocess.DEVNULL if stdin is None else None, input=stdin,
    )
    return SimpleNamespace(
        returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr,
    )


def git(context, *args, check=True):
    """Run git in the scenario repository."""
    result = run(context, ["git", *args])
    if check and result.returncode:
        raise AssertionError("git %s failed:\n%s" % (" ".join(args), result.stderr))
    return result


def head(context):
    """The current HEAD commit id, or None before the first commit."""
    result = git(context, "rev-parse", "--verify", "-q", "HEAD", check=False)
    return result.stdout.strip() or None


def leftblock(context, *args, stdin=None):
    """Run the LeftBlock CLI module from the current interpreter."""
    return run(context, [sys.executable, "-m", "leftblock.cli", *args], stdin=stdin)


def make_repository(context, name="repo"):
    """Create an isolated git repository with one empty commit."""
    context.repo = os.path.join(context.root, name)
    os.makedirs(context.repo)
    git(context, "init", "-q")
    git(context, "config", "user.name", "Spec Author")
    git(context, "config", "user.email", "spec.author@example.com")
    git(context, "config", "commit.gpgsign", "false")
    git(context, "commit", "-q", "--allow-empty", "-m", "initial commit")


def gitleaks_path():
    # Without gitleaks only scenarios that never scan can install; they get a
    # stand-in executable. Scenarios that scan carry the @gitleaks tag.
    return shutil.which("gitleaks") or "/usr/bin/true"


def write_file(context, name, content, append=False):
    path = os.path.join(context.repo, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a" if append else "w") as handle:
        handle.write(content)


def synthesize(context, kind):
    """Generate a synthetic ``kind`` and remember its secrets."""
    content, values = synthetic_data.make(kind, random.Random(kind))
    context.synthetic_values.extend(values)
    return content


def output(context):
    """stdout and stderr of the last command, joined."""
    return context.result.stdout + context.result.stderr
