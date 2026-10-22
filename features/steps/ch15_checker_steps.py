"""Steps for writing checker policies and stand-in checkers (chapters 11, 12, 15).

Policies are written by hand into the scenario repository, and the checkers
they name are small Python scripts written into a scratch folder of the
scenario's temporary root. Inside policy text and script arguments these
placeholders are expanded:

- ``$PYTHON``: the interpreter running the specs
- ``$CHECKERS``: the folder holding the checker scripts
- ``$SCRATCH``: the scenario's temporary root

Chapters 11 and 12 reuse these steps; behave shares steps across modules.
"""

import os
import re
import stat
import sys
import textwrap

from behave import given, then

import world


def _checkers_dir(context):
    path = os.path.join(context.root, "checkers")
    os.makedirs(path, exist_ok=True)
    return path


def _expand(context, text):
    return (
        text.replace("$PYTHON", sys.executable)
        .replace("$CHECKERS", _checkers_dir(context))
        .replace("$SCRATCH", context.root)
    )


def _policy_path(context):
    return os.path.join(context.repo, ".leftblock.yml")


# --- Given: policies and stand-in programs --------------------------------

@given('a checker script "{name}" containing:')
def step_checker_script(context, name):
    """Write the docstring (Python) as ``name`` in the checker scripts folder."""
    path = os.path.join(_checkers_dir(context), name)
    with open(path, "w") as handle:
        handle.write(textwrap.dedent(context.text).strip("\n") + "\n")


@given("the checker policy is:")
def step_policy_text(context):
    """Write the docstring as the repository's ``.leftblock.yml`` (placeholders expanded)."""
    with open(_policy_path(context), "w") as handle:
        handle.write(_expand(context, textwrap.dedent(context.text).strip("\n")) + "\n")


@given('the checker policy reads "{text}"')
def step_policy_line(context, text):
    """Write a one-line policy (usually flow-style YAML) as ``.leftblock.yml``."""
    with open(_policy_path(context), "w") as handle:
        handle.write(_expand(context, text) + "\n")


@given("the checker policy is empty")
def step_policy_empty(context):
    """Replace ``.leftblock.yml`` with an empty file."""
    open(_policy_path(context), "w").close()


@given("there is no checker policy")
def step_policy_absent(context):
    """Delete ``.leftblock.yml`` from the working tree."""
    if os.path.exists(_policy_path(context)):
        os.remove(_policy_path(context))


@given("a stand-in tactus program containing:")
def step_standin_tactus(context):
    """Put an executable ``tactus`` (Python, from the docstring) first on PATH."""
    bin_dir = os.path.join(context.root, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    path = os.path.join(bin_dir, "tactus")
    with open(path, "w") as handle:
        handle.write("#!" + sys.executable + "\n")
        handle.write(textwrap.dedent(context.text).strip("\n") + "\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    context.env["PATH"] = bin_dir + os.pathsep + context.env.get("PATH", "")


@given('the temporary directory is a private folder named "{name}"')
def step_private_tmp(context, name):
    """Point TMPDIR at a fresh folder ``name`` (it may contain spaces)."""
    path = os.path.join(context.root, name)
    os.makedirs(path)
    context.env["TMPDIR"] = path
    context.private_tmp = path


# --- Then -----------------------------------------------------------------

@then("nothing is left in the private temporary folder")
def step_private_tmp_empty(context):
    """No temporary report or index file survives in the private TMPDIR."""
    leftovers = os.listdir(context.private_tmp)
    assert not leftovers, "temporary files remain: %r" % leftovers


@then('neither stdout nor stderr shows "{text}"')
def step_never_shows(context, text):
    """``text`` appears in neither stream of the last command."""
    assert text not in world.output(context), "output shows %r" % text


@then("stderr shows no terminal escape sequences")
def step_no_escapes(context):
    """stderr of the last command has no ESC character."""
    assert "\x1b" not in context.result.stderr, repr(context.result.stderr)


@then("the finding description shown is {count:d} characters long")
def step_description_length(context, count):
    """The parenthesised description in the finding line is exactly ``count`` long."""
    found = re.findall(r"\((\w+)\)", context.result.stderr)
    assert found, context.result.stderr
    assert len(found[0]) == count, "description is %d characters" % len(found[0])


@then('the file "{name}" contains "{text}"')
def step_file_contains(context, name, text):
    """The repository file ``name`` contains ``text``."""
    with open(os.path.join(context.repo, name)) as handle:
        assert text in handle.read()


@then('the file "{name}" is identical to the packaged ruleset')
def step_file_is_packaged(context, name):
    """``name`` is a byte-for-byte copy of the ruleset shipped with LeftBlock."""
    packaged = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(world.__file__))),
        "leftblock", "data", "gitleaks.toml",
    )
    with open(packaged, "rb") as want, open(os.path.join(context.repo, name), "rb") as got:
        assert got.read() == want.read()


@then('the file "{name}" still reads:')
def step_file_still_reads(context, name):
    """The repository file ``name`` equals the docstring exactly."""
    with open(os.path.join(context.repo, name)) as handle:
        assert handle.read() == textwrap.dedent(context.text).strip("\n") + "\n"


@then('the scratch file "{name}" exists')
def step_scratch_exists(context, name):
    """A checker left ``name`` in the scenario's temporary root (proof it ran)."""
    assert os.path.exists(os.path.join(context.root, name)), name + " was not created"
