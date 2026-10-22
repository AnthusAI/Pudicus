"""Steps shared by chapter 13 (receipt mode) and chapter 14 (retroactive approval).

Both chapters work in a repository installed in receipt mode and look at the
commit message trailers LeftBlock writes. Chapter-specific steps for 13 and 14
that are not about trailers or unsigned history belong in ch13_/ch14_ modules.
"""

from behave import given, then

import world as common


def _unsigned_commit(context, name, content, message):
    # --no-verify skips the commit-msg hook, so the commit carries no receipt.
    common.write_file(context, name, content)
    common.git(context, "add", name)
    common.git(context, "commit", "-q", "--no-verify", "-m", message)


@given("a commit made without the hook")
def step_commit_without_hook(context):
    """One harmless commit created with --no-verify, so it has no receipt."""
    _unsigned_commit(context, "plain.txt", "safe code\n", "unsigned commit")


@given("{count:d} unsigned commits")
def step_unsigned_commits(context, count):
    """``count`` harmless commits created with --no-verify (no receipts)."""
    for i in range(count):
        _unsigned_commit(
            context, "unsigned_%d.txt" % i, "safe code %d\n" % i, "unsigned commit %d" % i
        )


@given("an unsigned commit containing a synthetic {kind}")
def step_unsigned_sensitive(context, kind):
    """One commit, made with --no-verify, whose file holds a synthetic ``kind``."""
    _unsigned_commit(
        context, "unsigned_secret.txt", common.synthesize(context, kind),
        "unsigned commit with sensitive data",
    )


@then('the latest commit message contains "{text}"')
def step_message_contains(context, text):
    """The message of HEAD contains ``text``."""
    message = common.git(context, "log", "-1", "--format=%B").stdout
    assert text in message, message


@then('the latest commit message does not contain "{text}"')
def step_message_lacks(context, text):
    """The message of HEAD does not contain ``text``."""
    message = common.git(context, "log", "-1", "--format=%B").stdout
    assert text not in message, message
