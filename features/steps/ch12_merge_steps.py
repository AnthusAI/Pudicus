"""Steps for chapter 12 (merge commits): building histories and merges.

History steps commit with --no-verify: they model content that arrived
earlier, possibly unchecked, and the scenario is about the merge that follows.
Merges are started with --no-commit so they can be inspected (``leftblock
check``) or concluded (``I commit the staged files``).
"""

import json
import os
import shlex
import sys

from behave import given, then

import world
from synthetic_data import generator, uuid4


@generator("flagged session line")
def _flagged_session_line(rng):
    return "session %s here\n" % uuid4(rng), []


@generator("another flagged session line")
def _another_flagged_session_line(rng):
    return "session %s here\n" % uuid4(rng), []


def _commit(context, message):
    world.git(context, "commit", "-q", "--no-verify", "-m", message)


@given('the history is on a branch called "{name}"')
def step_name_branch(context, name):
    """Rename the current branch so the scenario can refer to it."""
    world.git(context, "branch", "-m", name)


@given('a branch "{name}" is created from the current one and checked out')
def step_create_branch(context, name):
    world.git(context, "checkout", "-q", "-b", name)


@given('the branch "{name}" is checked out')
def step_checkout(context, name):
    world.git(context, "checkout", "-q", name)


@given('the current branch gains a commit adding "{name}" containing a synthetic {kind}')
def step_commit_synthetic(context, name, kind):
    """Add ``name`` with generated content in a new commit (hooks skipped)."""
    world.write_file(context, name, world.synthesize(context, kind))
    world.git(context, "add", name)
    _commit(context, "add " + name)


@given('the current branch gains a commit adding "{name}" containing:')
def step_commit_text(context, name):
    """Add ``name`` with the docstring as content in a new commit (hooks skipped)."""
    world.write_file(context, name, context.text.strip("\n") + "\n")
    world.git(context, "add", name)
    _commit(context, "add " + name)


@given('the current branch gains a commit replacing "{name}" with:')
def step_commit_replace(context, name):
    """Replace the content of ``name`` in a new commit (hooks skipped)."""
    world.write_file(context, name, context.text.strip("\n") + "\n")
    world.git(context, "add", name)
    _commit(context, "change " + name)


@given('the current branch gains a commit adding a symlink "{name}" whose target is a synthetic {kind}')
def step_commit_symlink(context, name, kind):
    """Commit a symbolic link whose target text is the generated value."""
    target = world.synthesize(context, kind).strip()
    os.symlink(target, os.path.join(context.repo, name))
    world.git(context, "add", name)
    _commit(context, "add link " + name)


@given('the current branch gains a commit renaming "{old}" to "{new}"')
def step_commit_rename(context, old, new):
    world.git(context, "mv", old, new)
    _commit(context, "rename " + old)


@given('a merge of "{branch}" is in progress, not yet committed')
def step_merge_started(context, branch):
    """Start merging ``branch`` and stop before the merge commit (conflicts allowed)."""
    world.git(context, "merge", "-q", "--no-commit", "--no-ff", branch, check=False)
    assert os.path.exists(os.path.join(context.repo, ".git", "MERGE_HEAD"))


@given('an octopus merge of "{first}" and "{second}" is in progress, not yet committed')
def step_octopus_started(context, first, second):
    world.git(context, "merge", "-q", "--no-commit", "--no-ff", first, second)
    with open(os.path.join(context.repo, ".git", "MERGE_HEAD")) as handle:
        assert len(handle.read().split()) == 2


@given('the staged file "{old}" is renamed to "{new}"')
def step_staged_rename(context, old, new):
    world.git(context, "mv", old, new)


@given('"{name}" is changed by one more harmless line and staged')
def step_stage_extra_line(context, name):
    world.write_file(context, name, "resolution adds a harmless line\n", append=True)
    world.git(context, "add", name)


@given('"{name}" is staged as executable')
def step_stage_executable(context, name):
    world.git(context, "update-index", "--chmod=+x", name)


@given('a binary file "{name}" and a submodule pointer "{path}" are staged')
def step_stage_binary_and_gitlink(context, name, path):
    with open(os.path.join(context.repo, name), "wb") as handle:
        handle.write(b"generated\0binary")
    world.git(context, "add", name)
    commit = world.git(context, "rev-parse", "HEAD").stdout.strip()
    world.git(context, "update-index", "--add", "--cacheinfo", "160000", commit, path)


_MERGE_HEAD_STATES = {
    "text that is not a commit id": lambda context: b"not-a-commit-id\n",
    "the id of a commit that does not exist": lambda context: b"f" * 40 + b"\n",
    "the id of a tree": lambda context: world.git(
        context, "rev-parse", "HEAD^{tree}").stdout.encode(),
    "nothing": lambda context: b"",
}


@given("the merge records {what} as its parent")
def step_corrupt_merge_head(context, what):
    """Overwrite MERGE_HEAD, or delete it for ``no merge in progress``."""
    path = os.path.join(context.repo, ".git", "MERGE_HEAD")
    if what == "no parent at all":
        os.remove(path)
        return
    with open(path, "wb") as handle:
        handle.write(_MERGE_HEAD_STATES[what](context))


@given('the local policy also flags the three-line block "{first}", "{second}", "{third}"')
def step_multiline_rule(context, first, second, third):
    """Swap the local gate's ruleset for one rule matching three consecutive lines."""
    rules = os.path.join(context.root, "multiline.toml")
    with open(rules, "w") as handle:
        handle.write(
            '[[rules]]\nid = "synthetic-multiline"\n'
            'description = "Generated multiline fixture"\n'
            "regex = '''%s\\n%s\\n%s'''\n" % (first, second, third)
        )
    common = world.git(context, "rev-parse", "--git-common-dir").stdout.strip()
    policy = os.path.join(context.repo, common, "leftblock", "policy.json")
    with open(policy) as handle:
        data = json.load(handle)
    argv = shlex.split(data["checkers"][0]["command"])
    argv[argv.index("--config") + 1] = rules
    data["checkers"][0]["command"] = shlex.join(argv)
    with open(policy, "w") as handle:
        json.dump(data, handle)


@then('"{name}" is still staged')
def step_still_staged(context, name):
    """The real index still lists ``name``."""
    listed = world.git(context, "ls-files", "--", name).stdout.split()
    assert name in listed, "%s is no longer staged" % name


@given("the local policy is replaced by:")
def step_replace_local_policy(context):
    """Write the docstring ($PYTHON and $CHECKERS expanded) as the local gate's policy."""
    common = world.git(context, "rev-parse", "--git-common-dir").stdout.strip()
    policy = os.path.join(context.repo, common, "leftblock", "policy.json")
    text = context.text.replace("$PYTHON", sys.executable).replace(
        "$CHECKERS", os.path.join(context.root, "checkers"))
    with open(policy, "w") as handle:
        handle.write(text.strip("\n") + "\n")
