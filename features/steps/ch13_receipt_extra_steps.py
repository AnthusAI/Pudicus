"""Steps for receipts beyond the basics (chapters 11, 13 and 14).

- Driving LeftBlock on an interactive terminal (a pseudo-terminal) so a human
  can type the shared passphrase.
- Reading and tampering with the receipt trailers of a commit.
- Recording reviewed overrides for the staged findings.

Behave shares steps across modules, so chapter 11 reuses the terminal steps.
"""

import hashlib
import hmac
import os
import pty
import re
import select
import shlex
import sys
import time

from behave import given, then, when

import world

REASON = "Reviewed by the team and confirmed not to be sensitive data."
MESSAGE = "test: staged content\n"


def _secret(context):
    with open(context.secret_path) as handle:
        return handle.read().strip()


def _message_file(context):
    path = os.path.join(context.root, "COMMIT_EDITMSG")
    if not os.path.exists(path):
        with open(path, "w") as handle:
            handle.write(MESSAGE)
    context.message_file = path
    return path


def _on_terminal(context, args, answer):
    """Run the CLI with a controlling terminal, typing ``answer`` at the prompt."""
    path = _message_file(context)
    argv = [sys.executable, "-m", "leftblock.cli"] + [
        path if part == "$MESSAGE_FILE" else part for part in shlex.split(args)
    ]
    context.head_before = world.head(context)
    pid, fd = pty.fork()
    if pid == 0:  # child: its terminal is the pseudo-terminal
        os.chdir(context.repo)
        os.execve(argv[0], argv, context.env)
    seen, sent = b"", False
    deadline = time.time() + world.TIMEOUT
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if not ready:
            continue
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        seen += data
        if not sent and b"passphrase" in seen and seen.rstrip().endswith(b":"):
            time.sleep(0.2)
            os.write(fd, answer.encode() + b"\n")
            sent = True
    else:
        os.kill(pid, 9)
    _, status = os.waitpid(pid, 0)
    # A terminal has a single stream; everything the person saw is "stderr".
    context.result = world.SimpleNamespace(
        returncode=os.waitstatus_to_exitcode(status), stdout="",
        stderr=seen.decode(errors="replace").replace("\r\n", "\n"),
    )
    context.was_commit = False


# --- Given ----------------------------------------------------------------

@given('a commit signed by the validator "{name}"')
def step_commit_signed_as(context, name):
    """Commit a harmless file with a genuine receipt naming validator ``name``."""
    world.write_file(context, "signed.txt", "signed content\n")
    world.git(context, "add", "signed.txt")
    tree = world.git(context, "write-tree").stdout.strip()
    stamp = "2026-01-01T00:00:00Z"
    mac = hmac.new(
        _secret(context).encode(), "|".join([tree, name, "clean", stamp]).encode(),
        hashlib.sha256,
    ).hexdigest()
    message = (
        "signed commit\n\nInspected-by: %s\nInspection-tree: %s\n"
        "Inspection-result: clean\nInspection-at: %s\nInspection-sig: hmac-sha256:%s\n"
        % (name, tree, stamp, mac)
    )
    world.git(context, "commit", "-q", "--no-verify", "-m", message)


@given("the staged findings are recorded as reviewed overrides")
def step_record_overrides(context):
    """Run ``leftblock check``, then ``leftblock allow`` for every finding id it prints."""
    blocked = world.leftblock(context, "check")
    ids = re.findall(r"\[id ([0-9a-f]{16})\]", blocked.stderr)
    assert ids, "no finding ids to override:\n" + blocked.stderr
    allowed = world.leftblock(context, "allow", *dict.fromkeys(ids), "--reason", REASON)
    assert allowed.returncode == 0, allowed.stderr


@given("the staged work is committed through the hook")
def step_commit_with_hook(context):
    """Commit the staged work normally, so the commit-msg hook adds a receipt."""
    result = world.git(context, "commit", "-q", "-m", "test: signed commit", check=False)
    assert result.returncode == 0, result.stderr


@given("the signing secret is replaced by a different one")
def step_secret_replaced(context):
    """Overwrite the shared secret with another value."""
    with open(context.secret_path, "w") as handle:
        handle.write("a-different-shared-secret-value")


@given("the signing secret has been removed")
def step_secret_removed(context):
    """Delete the shared signing secret generated at install."""
    os.remove(context.secret_path)


# --- When -----------------------------------------------------------------

@when('On an interactive terminal I run "leftblock {args}" and enter the shared passphrase')
def step_terminal_right_passphrase(context, args):
    """Run the command on a pseudo-terminal and type the real shared secret at the prompt.

    ``$MESSAGE_FILE`` in the arguments is a commit message file the scenario owns.
    """
    _on_terminal(context, args, _secret(context))


@when('On an interactive terminal I run "leftblock {args}" and enter a wrong passphrase')
def step_terminal_wrong_passphrase(context, args):
    """Run the command on a pseudo-terminal and type a passphrase that is not the secret."""
    _on_terminal(context, args, "not-the-shared-secret")


@when('the validator named in the latest receipt is changed to "{name}"')
def step_rename_validator(context, name):
    """Amend HEAD so its ``Inspected-by`` trailer names ``name``; the signature is untouched."""
    message = world.git(context, "log", "-1", "--format=%B").stdout
    changed = re.sub(r"^Inspected-by: .*$", "Inspected-by: " + name, message, flags=re.M)
    assert changed != message
    world.run(context, ["git", "commit", "-q", "--amend", "--no-verify", "-F", "-"], stdin=changed)


# --- Then -----------------------------------------------------------------

@then('the commit message file contains "{text}"')
def step_message_file_contains(context, text):
    """The message file given to the hook now contains ``text``."""
    with open(context.message_file) as handle:
        assert text in handle.read()


@then('the commit message file does not contain "{text}"')
def step_message_file_lacks(context, text):
    """The message file given to the hook does not contain ``text``."""
    with open(context.message_file) as handle:
        assert text not in handle.read()


@then("the receipt of the latest commit names the tree it actually contains")
def step_receipt_tree(context):
    """The ``Inspection-tree`` trailer of HEAD equals HEAD's real tree."""
    real = world.git(context, "rev-parse", "HEAD^{tree}").stdout.strip()
    message = world.git(context, "log", "-1", "--format=%B").stdout
    assert "Inspection-tree: " + real in message, message


@then("no signing secret exists")
def step_no_secret(context):
    """The shared secret file is absent."""
    assert not os.path.exists(context.secret_path)


@then("the latest commit is an empty commit directly on top of the previous HEAD")
def step_empty_on_top(context):
    """HEAD adds no changes and its only parent is the commit HEAD was before the last When."""
    parent = world.git(context, "rev-parse", "HEAD~1").stdout.strip()
    assert parent == context.head_before, "history was rewritten or branched"
    diff = world.git(context, "diff", "--stat", "HEAD~1", "HEAD").stdout
    assert diff.strip() == "", diff


@then("the latest commit message carries {count:d} receipts")
def step_receipt_count(context, count):
    """HEAD's message has ``count`` Inspection-tree trailers."""
    message = world.git(context, "log", "-1", "--format=%B").stdout
    found = len(re.findall(r"^Inspection-tree: ", message, re.M))
    assert found == count, "%d receipts, expected %d" % (found, count)
