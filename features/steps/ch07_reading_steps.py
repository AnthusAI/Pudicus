"""Chapter 7 (reading a block): steps that inspect the shape of blocked output.

``context.result.stderr`` carries the whole report. A finding line reads
``file:LINE: rule [id <16 hex>] (description)``; the last line is the ERROR
line that names every finding and the next step on its own.
"""

import hashlib
import json
import os
import re
import sys
from importlib.metadata import version

from behave import given, then

import world

FINDING = re.compile(
    r"^      (?P<file>.+?):(?P<line>\d+): (?P<rule>\S+)(?: \[id (?P<id>[0-9a-f]{16})\])?"
    r"(?: \((?P<description>.*)\))?$", re.MULTILINE)
ESCAPE = "\x1b"
SENTINEL = "scanner" + "-matched-" + "material"


def _lines(context):
    return context.result.stderr.rstrip("\n").splitlines()


def _findings(context):
    return list(FINDING.finditer(context.result.stderr))


# --- Givens -----------------------------------------------------------------

@given('the file "{name}" gets a synthetic {kind} appended and staged')
def step_modify_committed(context, name, kind):
    """``name`` gains one generated line at the end, staged."""
    world.write_file(context, name, world.synthesize(context, kind), append=True)
    world.git(context, "add", name)


@given("a root .gitleaksignore file exists")
def step_gitleaksignore(context):
    world.write_file(context, ".gitleaksignore", "# reviewed exceptions\n")


@given("NO_COLOR is not set")
def step_no_color_unset(context):
    context.env.pop("NO_COLOR", None)


@given("NO_COLOR is set")
def step_no_color_set(context):
    context.env["NO_COLOR"] = "1"


@given("the repository policy runs gitleaks without a rules file")
def step_policy_without_rules(context):
    command = "%s protect --staged --redact --no-banner --report-format json --report-path {report_file}" % (
        world.gitleaks_path())
    policy = {"version": 1, "checkers": [{
        "name": "gitleaks", "type": "command", "command": command,
        "success_codes": [0], "finding_codes": [1]}]}
    world.write_file(context, ".leftblock.yml", json.dumps(policy))


def _scanner_policy(context, finding):
    script = os.path.join(context.root, "scanner.py")
    with open(script, "w") as handle:
        handle.write(
            "import json, sys\n"
            "json.dump([%r], open(sys.argv[1], 'w'))\n"
            "print(%r)\nprint(%r, file=sys.stderr)\n"
            "sys.exit(1)\n" % (finding, SENTINEL, SENTINEL))
    command = "%s %s {report_file}" % (sys.executable, script)
    policy = {"version": 1, "checkers": [{
        "name": "scripted", "type": "command", "command": command,
        "success_codes": [0], "finding_codes": [1]}]}
    world.write_file(context, ".leftblock.yml", json.dumps(policy))
    context.synthetic_values.append(SENTINEL)


def _report(description):
    return {"File": "page.txt", "RuleID": "scripted-rule", "StartLine": 1, "EndLine": 1,
            "Description": description, "Match": SENTINEL, "Secret": SENTINEL, "Line": SENTINEL}


@given("a scanner reports a finding with a description of {count:d} characters")
def step_long_description(context, count):
    _scanner_policy(context, _report("x" * count))


@given("a scanner reports a finding whose description contains a terminal escape sequence")
def step_hostile_description(context):
    _scanner_policy(context, _report("bad" + ESCAPE + "[31m text"))


@given("LeftBlock is not on the command path and the interpreter lives under the home directory")
def step_off_path_under_home(context):
    """Hide any ``leftblock`` command and make the interpreter's environment
    the scenario's HOME, so the printed fallback command must shorten it."""
    tools = os.path.join(context.root, "tools")
    os.makedirs(tools, exist_ok=True)
    for tool in ("git", "gitleaks"):
        found = _which(tool)
        if found and not os.path.exists(os.path.join(tools, tool)):
            os.symlink(found, os.path.join(tools, tool))
    context.env["PATH"] = tools
    context.env["HOME"] = os.path.dirname(os.path.dirname(os.path.abspath(sys.executable)))
    context.shown_home = context.env["HOME"]


def _which(tool):
    import shutil
    return shutil.which(tool)


@given("LeftBlock is on the command path")
def step_on_path(context):
    here = os.path.dirname(os.path.abspath(sys.executable))
    if not os.path.exists(os.path.join(here, "leftblock")):
        context.scenario.skip("no leftblock command beside this interpreter")
        return
    context.env["PATH"] = here + os.pathsep + context.env["PATH"]


# --- Thens ------------------------------------------------------------------

@then("the first line of stderr names the installed version and the ruleset hash")
def step_first_line(context):
    with open(os.path.join(context.repo, ".git", "leftblock", "gitleaks.toml"), "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()[:12]
    first = _lines(context)[0]
    assert first.endswith("leftblock %s, ruleset %s" % (version("leftblock"), digest)), first


@then("the first line of stderr names the installed version and the ruleset as unknown")
def step_first_line_unknown(context):
    first = _lines(context)[0]
    assert first.endswith("leftblock %s, ruleset unknown" % version("leftblock")), first


@then('stderr lists "{rule}" for "{name}" at line {line:d} described as "{text}"')
def step_finding_line(context, rule, name, line, text):
    expected = [m for m in _findings(context)
                if (m["file"], int(m["line"]), m["rule"], m["description"]) == (name, line, rule, text)]
    assert expected, "no finding line for %s:%s %s (%s) in:\n%s" % (
        name, line, rule, text, context.result.stderr)


@then('stderr lists "{rule}" for "{name}" at line {line:d}')
def step_finding_line_plain(context, rule, name, line):
    expected = [m for m in _findings(context)
                if (m["file"], int(m["line"]), m["rule"]) == (name, line, rule)]
    assert expected, "no finding line for %s:%s %s in:\n%s" % (
        name, line, rule, context.result.stderr)


@then("every listed finding carries an id of sixteen hexadecimal characters")
def step_ids(context):
    found = _findings(context)
    assert found, "no finding lines:\n" + context.result.stderr
    assert all(m["id"] and len(m["id"]) == 16 for m in found)


@then('stderr shows "{text}" {count:d} time')
@then('stderr shows "{text}" {count:d} times')
def step_stderr_count(context, text, count):
    actual = context.result.stderr.count(text)
    assert actual == count, "%r appears %d times, expected %d:\n%s" % (
        text, actual, count, context.result.stderr)


@then("stderr shows a description of exactly {count:d} \"x\" characters")
def step_description_length(context, count):
    descriptions = [m["description"] for m in _findings(context)]
    assert descriptions == ["x" * count], descriptions


@then("stderr contains no terminal escape characters")
def step_no_escapes(context):
    assert ESCAPE not in context.result.stderr, repr(context.result.stderr)


@then('the last line of stderr contains "{text}"')
def step_last_contains(context, text):
    assert text in _lines(context)[-1], _lines(context)[-1]


@then('the last line of stderr starts with the ERROR label "{text}"')
def step_last_label(context, text):
    assert _lines(context)[-1].startswith("[leftblock ERROR] " + text), _lines(context)[-1]


@then("the last line of stderr names every listed finding by rule, file, line and id")
def step_last_names_all(context):
    last = _lines(context)[-1]
    found = _findings(context)
    assert found, "no finding lines:\n" + context.result.stderr
    for m in found:
        part = "%s in %s:%s [id %s]" % (m["rule"], m["file"], m["line"], m["id"])
        assert part in last, "%r missing from %r" % (part, last)


@then("the last line of stderr offers the allow command for every listed id")
def step_last_allow(context):
    last = _lines(context)[-1]
    ids = list(dict.fromkeys(m["id"] for m in _findings(context)))
    assert " allow %s" % " ".join(ids) in last, last
    assert '--reason "<why this is not sensitive>"' in last, last


@then("no line of stderr contains the home directory")
def step_no_home(context):
    home = context.env["HOME"]
    assert home, "no home"
    for line in context.result.stderr.splitlines():
        assert home + os.sep not in line, line


@then('the printed commands begin with "{prefix}"')
def step_command_prefix(context, prefix):
    commands = re.findall(r"(?:Re-run this check: |record a reviewed override: )(\S+)",
                          context.result.stderr)
    assert commands and all(c == prefix for c in commands), (commands, context.result.stderr)


@then("the printed commands show the interpreter path with the home directory as a tilde")
def step_tilde(context):
    assert re.search(r"Re-run this check: ~/\S*python\S* -I -B -m leftblock\.cli check",
                     context.result.stderr), context.result.stderr
