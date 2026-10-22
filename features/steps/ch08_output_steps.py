"""Steps for chapter 8: the dry run and its machine-readable output.

Chapter-specific; the shared vocabulary lives in common_steps.py.
"""

import json
import re
from importlib.metadata import version

from behave import given, step, then

import world


def _report(context):
    try:
        return json.loads(context.result.stdout)
    except ValueError:
        raise AssertionError("stdout is not JSON:\n" + context.result.stdout)


def _node(context, field):
    node = _report(context)
    for part in field.split("."):
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def _write_root_policy(context, command):
    policy = {"version": 1, "checkers": [
        {"name": "spec-scanner", "type": "command", "command": command},
    ]}
    # JSON is valid YAML and avoids quoting ambiguity.
    world.write_file(context, ".leftblock.yml", json.dumps(policy))


@given("a root policy whose only scanner accepts everything")
def step_root_policy_accepts(context):
    """A .leftblock.yml at the repository root with a scanner that always passes."""
    _write_root_policy(context, "/usr/bin/true")


@given("a root policy whose only scanner always reports a finding")
def step_root_policy_rejects(context):
    """A .leftblock.yml at the repository root with a scanner that always fails."""
    _write_root_policy(context, "/usr/bin/false")


@given("an override is recorded for the staged finding because \"{reason}\"")
def step_override_recorded(context, reason):
    """Run a dry run, take the one finding id it shows and record an override."""
    check = world.leftblock(context, "check")
    ids = re.findall(r"\[id ([0-9a-f]{16})\]", check.stderr)
    assert ids, "the dry run showed no finding id:\n" + check.stderr
    allowed = world.leftblock(context, "allow", ids[0], "--reason", reason)
    assert allowed.returncode == 0, allowed.stderr


@given("I remember the staged tree")
def step_remember_tree(context):
    """Record the staged tree id and staged file names."""
    context.remembered_tree = world.git(context, "write-tree").stdout
    context.remembered_names = world.git(context, "diff", "--cached", "--name-only").stdout


@then("the staged tree is exactly as remembered")
def step_tree_unchanged(context):
    """The index tree and staged file names did not change."""
    assert world.git(context, "write-tree").stdout == context.remembered_tree
    names = world.git(context, "diff", "--cached", "--name-only").stdout
    assert names == context.remembered_names


@then("the dry run prints nothing on stdout")
def step_stdout_empty(context):
    """Standard output is completely empty."""
    assert context.result.stdout == "", context.result.stdout


@then("the version line names the installed LeftBlock")
def step_version_line(context):
    """stdout is exactly ``leftblock <installed version>``."""
    expected = "leftblock " + version("leftblock")
    assert context.result.stdout.strip() == expected, context.result.stdout


@then('the JSON report has a version equal to the installed version')
def step_json_version(context):
    """The report's version field is the installed LeftBlock version."""
    assert _node(context, "version") == version("leftblock")


@then("the JSON finding has a 16-character hexadecimal id")
def step_json_finding_id(context):
    """The first finding carries an id of 16 lowercase hex characters."""
    assert re.fullmatch(r"[0-9a-f]{16}", _node(context, "findings.0.id"))


@then('the JSON field "{field}" contains "{text}"')
def step_json_contains(context, field, text):
    """A string field of the report contains ``text``."""
    assert text in str(_node(context, field)), _node(context, field)


@then("the override command in the report names the finding id")
def step_json_command_id(context):
    """override_command repeats the id of the first finding."""
    ident = _node(context, "findings.0.id")
    assert ident in _node(context, "override_command")


@then("the JSON override applied has the id of the recorded override")
def step_json_applied_id(context):
    """overrides_applied.0.id is the id recorded in the staged allow file."""
    staged = world.git(context, "show", ":.leftblock-allow.yml").stdout
    ident = re.search(r'id: "([0-9a-f]{16})"', staged).group(1)
    assert _node(context, "overrides_applied.0.id") == ident
