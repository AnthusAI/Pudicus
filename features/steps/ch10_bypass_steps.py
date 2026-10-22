"""Steps for chapter 10: silent scanner bypasses (inline markers, ignore files).

The scanner's inline allow marker is assembled at run time: written literally
anywhere in this repository it would itself be a finding.
"""

import os
import random
import re

from behave import given, step, then

import world
from synthetic_data import LOWER, token

MARKER = "gitleaks" + ":allow"
FINDING_ID = re.compile(r"^      .*\[id ([0-9a-f]{16})\](?: \(.*\))?$", re.MULTILINE)
WORDS = ["one", "two", "three", "four", "five", "six"]


def _read(context, name):
    with open(os.path.join(context.repo, name)) as handle:
        return handle.read()


@step('a staged notes file "{name}" of {total:d} lines with the inline allow marker on line {n:d}')
def step_marked_file(context, name, total, n):
    """``total`` short lines; line ``n`` ends with a comment holding the marker."""
    lines = [WORDS[i] for i in range(total)]
    lines[n - 1] += " # harmless " + MARKER
    world.write_file(context, name, "\n".join(lines) + "\n")
    world.git(context, "add", name)


@given('a committed notes file "{name}" whose first line carries the inline allow marker')
def step_committed_marked(context, name):
    """Commit, without the hook, two lines of which the first carries the marker."""
    world.write_file(context, name, "one # " + MARKER + "\ntwo\n")
    world.git(context, "add", name)
    world.git(context, "commit", "-q", "--no-verify", "-m", "chore: add " + name)


@step('a staged notes file "{name}" with a personal address and the inline allow marker on one line')
def step_marked_address(context, name):
    """One line holding a generated address followed by the marker."""
    rng = random.Random("bypass address")
    value = token(rng, 6, LOWER) + "." + token(rng, 7, LOWER) + "@" + token(rng, 9, LOWER) + ".com"
    context.synthetic_values.append(value)
    world.write_file(context, name, "mail %s # %s\n" % (value, MARKER))
    world.git(context, "add", name)


@step('I stage "{name}" with one more plain line')
def step_more_line(context, name):
    """Append one harmless line and stage the file."""
    world.write_file(context, name, "three\n", append=True)
    world.git(context, "add", name)


@step('I stage "{name}" with one more line carrying the inline allow marker')
def step_more_marked_line(context, name):
    """Append a third line that carries the marker and stage the file."""
    world.write_file(context, name, "three # " + MARKER + "\n", append=True)
    world.git(context, "add", name)


@step('I stage "{name}" with the inline allow marker removed')
def step_marker_removed(context, name):
    """Delete the marker comments from the file and stage it."""
    text = _read(context, name).replace(" # " + MARKER, "")
    assert MARKER not in text
    world.write_file(context, name, text)
    world.git(context, "add", name)


@step('I stage "{name}" with its marker line edited')
def step_marker_edited(context, name):
    """Change the marked line (the marker stays) and stage the file."""
    world.write_file(context, name, _read(context, name).replace(MARKER, MARKER + " (edited)"))
    world.git(context, "add", name)


@step('I stage the removal of "{name}"')
def step_stage_removal(context, name):
    """``git rm`` the file, staging its deletion."""
    world.git(context, "rm", "-q", "-f", name)


@step("I note the ids the bypass check reports")
def step_note_bypass_ids(context):
    """Run ``leftblock check``; it must block, and its finding ids are remembered."""
    context.result = world.leftblock(context, "check")
    assert context.result.returncode == 1, context.result.stderr
    context.bypass_ids = FINDING_ID.findall(context.result.stderr)
    assert context.bypass_ids, context.result.stderr


@step('I record overrides for the reported bypasses because "{reason}"')
def step_record_bypass(context, reason):
    """``leftblock allow`` for every id the bypass check reported."""
    context.result = world.leftblock(context, "allow", *context.bypass_ids, "--reason", reason)
    assert context.result.returncode == 0, context.result.stderr


@given("the working tree has a root ignore file with no entries")
def step_unstaged_root_ignore(context):
    """A root ``.gitleaksignore`` that is neither staged nor committed."""
    world.write_file(context, ".gitleaksignore", "# no entries\n")


@given('a committed root ignore file that skips the personal email finding on line 1 of "{name}"')
def step_committed_root_ignore(context, name):
    """Commit (without the hook) a root ignore file naming rule, file and line."""
    world.write_file(context, ".gitleaksignore", "%s:leftblock-personal-email:1\n" % name)
    world.git(context, "add", ".gitleaksignore")
    world.git(context, "commit", "-q", "--no-verify", "-m", "chore: add ignore file")


@then("the reported bypasses are {count:d}")
def step_bypass_count(context, count):
    """The last blocked check listed exactly ``count`` findings with ids."""
    assert len(FINDING_ID.findall(context.result.stderr)) == count, context.result.stderr
