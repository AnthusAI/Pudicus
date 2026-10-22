"""Shared step vocabulary for every chapter. Do not redefine these steps.

Every scenario runs in the world built by features/environment.py:
``context.env`` (isolated HOME, LEFTBLOCK_HOME and secret path), and, once a
repository step has run, ``context.repo`` (a path), ``context.result`` (the
last command: ``returncode``, ``stdout``, ``stderr``) and
``context.synthetic_values`` (secrets generated so far, which no output may
reveal).

Synthetic values come from features/synthetic_data.py; see features/steps/
README.md for the vocabulary reference.
"""

import json
import os
import shlex
import textwrap

from behave import given, then, when

from world import (
    COMMIT_MESSAGE, git, gitleaks_path, head, leftblock, make_repository,
    output, synthesize, write_file,
)


# --- Given: repositories --------------------------------------------------

@given("a repository without LeftBlock")
def step_plain_repository(context):
    """An empty git repository with one commit and no LeftBlock installed."""
    make_repository(context)


@given("a repository with LeftBlock installed as a local check-only gate")
def step_local_gate(context):
    """Create a repository and run ``leftblock install --local --check-only``.

    Uses the current interpreter and the gitleaks on PATH (a stand-in when
    absent). The managed pre-commit hook then guards every commit. Tag the
    scenario @gitleaks if it scans anything.
    """
    make_repository(context)
    result = leftblock(
        context, "install", "--local", "--check-only", "--gitleaks", gitleaks_path()
    )
    assert result.returncode == 0, "install failed:\n" + result.stderr
    context.result = result


@given("a repository with LeftBlock installed in receipt mode")
def step_receipt_mode(context):
    """Create a repository and run the plain ``leftblock install``.

    Installs the commit-msg hook, writes .leftblock.yml and .leftblock/ rules
    (staged, ready for the first commit) and generates the signing secret at
    ``context.secret_path`` inside the scenario's temporary HOME.
    """
    make_repository(context)
    result = leftblock(context, "install")
    assert result.returncode == 0, "install failed:\n" + result.stderr
    git(context, "add", ".leftblock.yml", ".leftblock")
    context.result = result


# --- Given: files ---------------------------------------------------------

@given('a staged file "{name}" containing:')
def step_staged_text(context, name):
    """Write the docstring as file ``name`` and stage it.

    Never put real or key-shaped literals in a docstring; use the
    synthetic-kind step for anything sensitive.
    """
    write_file(context, name, textwrap.dedent(context.text).strip("\n") + "\n")
    git(context, "add", name)


@given('a staged file "{name}" containing a synthetic {kind}')
def step_staged_synthetic(context, name, kind):
    """Write a generated value of ``kind`` into file ``name`` and stage it."""
    write_file(context, name, synthesize(context, kind))
    git(context, "add", name)


@given('the file "{name}" is committed')
def step_file_committed(context, name):
    """Commit whatever is staged, plus ``name`` (harmless text if it is new).

    Setup only: it commits with --no-verify, so the gate is not involved and
    nothing in the history needs a receipt.
    """
    if not os.path.exists(os.path.join(context.repo, name)):
        write_file(context, name, "committed baseline\n")
    git(context, "add", name)
    git(context, "commit", "-q", "--no-verify", "-m", "chore: add " + name)


@given('an unstaged change to "{name}" containing a synthetic {kind}')
def step_unstaged_synthetic(context, name, kind):
    """Append a generated value of ``kind`` to ``name`` without staging it."""
    write_file(context, name, synthesize(context, kind), append=True)


# --- When -----------------------------------------------------------------

@when("I commit the staged files")
def step_commit(context):
    """Run ``git commit -m "test: staged content"`` with the gate in place.

    The result is kept in ``context.result``; stderr carries the hook output.
    """
    context.head_before = head(context)
    context.result = git(context, "commit", "-m", COMMIT_MESSAGE, check=False)
    context.was_commit = True


@when('I run "leftblock {args}"')
def step_run_cli(context, args):
    """Run the LeftBlock CLI (``python -m leftblock.cli``) in the repository.

    Arguments are split like a shell would. Standard input is closed, so the
    command has no terminal to prompt on.
    """
    context.head_before = head(context) if context.repo else None
    context.result = leftblock(context, *shlex.split(args))
    context.was_commit = False


# --- Then -----------------------------------------------------------------

@then("the commit is blocked")
def step_blocked(context):
    """The last commit exited nonzero."""
    assert context.result.returncode != 0, "commit unexpectedly succeeded"


@then("the commit succeeds")
def step_succeeds(context):
    """The last commit exited zero and HEAD moved."""
    assert context.result.returncode == 0, (
        "commit failed (%s):\n%s" % (context.result.returncode, context.result.stderr)
    )
    assert head(context) != context.head_before, "HEAD did not move"


@then("HEAD has not moved")
def step_head_unmoved(context):
    """HEAD is the commit it was before the last When step."""
    assert head(context) == context.head_before, "HEAD moved"


@then("the exit code is {code:d}")
def step_exit_code(context, code):
    """The last command exited with ``code``."""
    assert context.result.returncode == code, (
        "exit code %s, expected %s\nstdout:\n%s\nstderr:\n%s"
        % (context.result.returncode, code, context.result.stdout, context.result.stderr)
    )


@then('stderr contains "{text}"')
def step_stderr_contains(context, text):
    """The last command's stderr contains ``text`` (case-sensitive)."""
    assert text in context.result.stderr, context.result.stderr


@then('stderr does not contain "{text}"')
def step_stderr_lacks(context, text):
    """The last command's stderr does not contain ``text``."""
    assert text not in context.result.stderr, context.result.stderr


@then('stdout contains "{text}"')
def step_stdout_contains(context, text):
    """The last command's stdout contains ``text`` (case-sensitive)."""
    assert text in context.result.stdout, context.result.stdout


@then('stdout does not contain "{text}"')
def step_stdout_lacks(context, text):
    """The last command's stdout does not contain ``text``."""
    assert text not in context.result.stdout, context.result.stdout


@then('stdout is valid JSON with "{field}" equal to "{value}"')
def step_stdout_json(context, field, value):
    """stdout parses as JSON and ``field`` equals ``value``.

    ``field`` is a dotted path through objects and list indexes
    (``findings.0.rule``); the value is compared as text, so ``null`` and
    ``true`` are written as such.
    """
    try:
        node = json.loads(context.result.stdout)
    except ValueError:
        raise AssertionError("stdout is not JSON:\n" + context.result.stdout)
    for part in field.split("."):
        node = node[int(part)] if isinstance(node, list) else node[part]
    shown = json.dumps(node) if not isinstance(node, str) else node
    assert shown == value, "%s is %r, expected %r" % (field, shown, value)


@then("the output does not reveal the synthetic value")
def step_no_reveal(context):
    """Neither stdout nor stderr contains any generated secret so far."""
    assert context.synthetic_values, "no synthetic value was generated"
    text = output(context)
    for value in context.synthetic_values:
        assert value not in text, "output reveals a synthetic value"
