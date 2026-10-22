"""Steps for chapter 2 (stable runtime and upgrades).

A "runtime" is a throwaway virtual environment inside the scenario's temporary
root, holding its own copy of LeftBlock (and PyYAML). Installing the gate from
a runtime is what links ``$LEFTBLOCK_HOME/current`` and ``~/.local/bin/
leftblock``; both live under the scenario's temporary HOME, so the real home
directory is never touched.
"""

import os
import shutil
import sys
import venv

import yaml
from behave import given, then, when

import world

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc")


# --- helpers ---------------------------------------------------------------

def _runtime_dir(context, name):
    return os.path.join(context.root, "runtime-" + name)


def _runtime_python(context, name):
    return os.path.join(_runtime_dir(context, name), "bin", "python")


def _current(context):
    return os.path.join(context.leftblock_home, "current")


def _command_link(context):
    return os.path.join(context.home, ".local", "bin", "leftblock")


def _hook_path(context):
    result = world.run(
        context, ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
    )
    return os.path.join(result.stdout.strip(), "hooks", "pre-commit")


def _hook_text(context):
    with open(_hook_path(context)) as handle:
        return handle.read()


def _install_from(context, name):
    """Install the local gate with the runtime's own interpreter."""
    env = {k: v for k, v in context.env.items() if k != "PYTHONPATH"}
    saved, context.env = context.env, env
    try:
        return world.run(context, [
            _runtime_python(context, name), "-I", "-m", "leftblock.cli",
            "install", "--local", "--check-only", "--gitleaks", world.gitleaks_path(),
        ])
    finally:
        context.env = saved


# --- Given -----------------------------------------------------------------

@given('a runtime environment "{name}" with LeftBlock installed')
def step_runtime(context, name):
    """A virtual environment of its own that carries LeftBlock and PyYAML."""
    path = _runtime_dir(context, name)
    venv.EnvBuilder(with_pip=False, system_site_packages=True).create(path)
    packages = next((path_ for path_ in
                     [os.path.join(path, "lib", d, "site-packages")
                      for d in os.listdir(os.path.join(path, "lib"))]
                     if os.path.isdir(path_)))
    shutil.copytree(os.path.join(PROJECT_ROOT, "leftblock"),
                    os.path.join(packages, "leftblock"), ignore=IGNORE)
    shutil.copytree(os.path.dirname(yaml.__file__),
                    os.path.join(packages, "yaml"), ignore=IGNORE)


@given('the repository is guarded from the runtime environment "{name}"')
def step_guard_from(context, name):
    """Install the local gate in the current repository from runtime ``name``."""
    result = _install_from(context, name)
    assert result.returncode == 0, result.stderr
    context.hooks = getattr(context, "hooks", {})
    context.hooks[context.repo] = _hook_text(context)


@given('another repository "{repo}" guarded from the runtime environment "{name}"')
def step_second_repository(context, repo, name):
    """A second repository whose gate was installed from runtime ``name``."""
    world.make_repository(context, repo)
    step_guard_from(context, name)


@given("the runtime link points to a path that does not exist")
def step_broken_link(context):
    """Break ``current`` so it points nowhere."""
    os.unlink(_current(context))
    os.symlink(os.path.join(context.root, "gone"), _current(context))


@given("the runtime and command links already point to an old, missing runtime")
def step_stale_links(context):
    """Pre-existing links, left over from an environment that no longer exists."""
    os.makedirs(os.path.dirname(_command_link(context)))
    os.symlink("/nonexistent/old-runtime", _current(context))
    os.symlink("/nonexistent/old-command", _command_link(context))


@given("the user has their own script at the command location")
def step_own_command(context):
    """A regular file where the ``leftblock`` command link would go."""
    os.makedirs(os.path.dirname(_command_link(context)), exist_ok=True)
    with open(_command_link(context), "w") as handle:
        handle.write("#!/bin/sh\n# the user's own script\n")


@given("the runtime link location holds a directory")
def step_current_directory(context):
    """``current`` exists but is a real directory, not a symlink."""
    os.makedirs(_current(context))


# --- When ------------------------------------------------------------------

@given('I install the local gate from the runtime environment "{name}"')
@when('I install the local gate from the runtime environment "{name}"')
def step_install_from(context, name):
    """Run the installer with the runtime's own interpreter."""
    context.result = _install_from(context, name)


@when("I install the local gate from an interpreter outside any virtualenv")
def step_install_outside(context):
    """Run the installer in a process that sees no virtualenv (prefix == base prefix)."""
    context.result = world.run(context, [
        sys.executable, "-c",
        "import sys; sys.base_prefix = sys.prefix; sys.argv = ['leftblock', 'install', "
        "'--local', '--check-only', '--gitleaks', %r]; "
        "from leftblock import cli; cli.main()" % world.gitleaks_path(),
    ])


@when("I run the pre-commit hook directly")
def step_run_hook(context):
    """Execute the hook script with ``sh``, as Git would."""
    context.result = world.run(context, ["sh", _hook_path(context)])


# --- Then ------------------------------------------------------------------

@then('the runtime link points to the environment "{name}"')
def step_link_points(context, name):
    """``$LEFTBLOCK_HOME/current`` is a symlink to the runtime's real path."""
    current = _current(context)
    assert os.path.islink(current), "current is not a symlink"
    assert os.readlink(current) == os.path.realpath(_runtime_dir(context, name))


@then("the leftblock command in the user's bin directory links to the runtime")
def step_command_links(context):
    """``~/.local/bin/leftblock`` is a symlink to ``current/bin/leftblock``."""
    command = _command_link(context)
    assert os.path.islink(command), "no command link"
    assert os.readlink(command) == os.path.join(_current(context), "bin", "leftblock")


@then("the hook runs LeftBlock through the runtime link")
def step_hook_through_link(context):
    """The hook names ``current/bin/python`` and never the installing interpreter."""
    text = _hook_text(context)
    python = os.path.join(_current(context), "bin", "python")
    assert "PY=" + python in text, text
    assert 'exec "$PY" -I -B -m leftblock.cli check --config' in text, text
    assert os.path.join(context.root, "runtime-") not in text, text


@then("the hook runs LeftBlock with the installing interpreter directly")
def step_hook_direct(context):
    """Outside a virtualenv the hook execs the installing interpreter, no guard."""
    text = _hook_text(context)
    assert "exec %s -I -B -m leftblock.cli" % sys.executable in text, text
    assert "not installed" not in text


@then("the install reports the new links")
def step_reports_links(context):
    """stderr says the runtime and command were linked."""
    assert "Runtime link" in context.result.stderr, context.result.stderr
    assert "Linked" in context.result.stderr, context.result.stderr


@then("the install reports no link changes")
def step_reports_no_links(context):
    """Nothing about links is reported when they are already right."""
    assert "Runtime link" not in context.result.stderr, context.result.stderr
    assert "Linked" not in context.result.stderr, context.result.stderr


@then("the user's own script is untouched")
def step_own_command_intact(context):
    """The regular file at the command location is still a regular file."""
    command = _command_link(context)
    assert not os.path.islink(command)
    with open(command) as handle:
        assert handle.read() == "#!/bin/sh\n# the user's own script\n"


@then("the installer warns that it left the user's script alone")
def step_warns_own_script(context):
    """stderr mentions the untouched regular file."""
    assert "left untouched" in context.result.stderr, context.result.stderr


@then("no runtime link and no command link exist")
def step_no_links(context):
    """Neither ``current`` nor the command link was created."""
    assert not os.path.lexists(_current(context))
    assert not os.path.lexists(_command_link(context))


@then("no command link exists")
def step_no_command_link(context):
    """The command link was not created."""
    assert not os.path.lexists(_command_link(context))


@then("the hooks of every repository are exactly as they were installed")
def step_hooks_unchanged(context):
    """No hook was rewritten: each still holds the bytes first installed."""
    for repo, text in context.hooks.items():
        context.repo = repo
        assert _hook_text(context) == text, repo


@then("the hook fails with a reinstall message naming the missing interpreter")
def step_reinstall_message(context):
    """Exit 1 and the exact fail-closed message on stderr."""
    assert context.result.returncode == 1, context.result.returncode
    python = os.path.join(_current(context), "bin", "python")
    expected = (
        "LeftBlock is not installed at %s. Reinstall: python -m pip install leftblock, "
        "then run 'leftblock install --local --check-only' in this repository." % python
    )
    assert context.result.stderr.strip() == expected, context.result.stderr
