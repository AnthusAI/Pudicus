"""Steps for chapter 1 (installing the local gate) and its receipt-mode section.

Everything here is about what installation writes, what it refuses to touch
and where it keeps its files. The shared steps (``a repository with LeftBlock
installed as a local check-only gate``, ``I run "leftblock ..."``, ...) live in
common_steps.py and are not redefined.

Refusal scenarios follow one pattern: record the repository state, run the
installer, assert the failure and assert that nothing changed since the
recording.
"""

import hashlib
import json
import os
import shlex
import shutil
import stat
import sys

from behave import given, then, when

import world

OWNER_HOOK = "#!/bin/sh\n# owner hook\nexit 7\n"
OWNER_FILE_TEXT = "owner content\n"

# Names the feature file uses for the files of the local gate.
LOCAL_PARTS = {
    "hook": ("hooks", "pre-commit"),
    "policy": ("leftblock", "policy.json"),
    "rules": ("leftblock", "gitleaks.toml"),
    "state": ("hooks", ".leftblock-pre-commit.json"),
}
RECEIPT_PARTS = {
    "commit-msg hook": ("hooks", "commit-msg"),
    "ownership state": ("hooks", ".leftblock-commit-msg.json"),
}


# --- helpers ---------------------------------------------------------------

def _common_dir(context, cwd=None):
    result = world.run(
        context, ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        cwd=cwd or context.repo,
    )
    assert result.returncode == 0, result.stderr
    return os.path.realpath(result.stdout.strip())


def _gate_path(context, part, table=LOCAL_PARTS):
    sub, name = table[part]
    return os.path.join(_common_dir(context), sub, name)


def _read(path):
    with open(path, "rb") as handle:
        return handle.read()


def _mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def _snapshot(context):
    """Everything an installer could touch: tree, hooks, policy, config, status."""
    tree, git = {}, {}
    gitdir = _common_dir(context)
    for current, dirs, files in os.walk(context.repo):
        dirs[:] = [d for d in dirs if os.path.realpath(os.path.join(current, d)) != gitdir]
        for name in files:
            path = os.path.join(current, name)
            tree[os.path.relpath(path, context.repo)] = (
                _read(path), _mode(path), os.path.islink(path),
            )
    for sub in ("hooks", "leftblock"):
        for current, _, files in os.walk(os.path.join(gitdir, sub)):
            for name in files:
                if name.endswith(".sample"):
                    continue
                path = os.path.join(current, name)
                link = os.readlink(path) if os.path.islink(path) else None
                git[os.path.relpath(path, gitdir)] = (
                    None if os.path.isdir(path) else _read(path) if link is None else None,
                    _mode(path), link, os.lstat(path).st_mtime_ns,
                )
    git["config"] = _read(os.path.join(gitdir, "config"))
    git["status"] = world.git(context, "status", "--porcelain=v1", "-z").stdout
    return tree, git


def _owner_file(context):
    path = os.path.join(context.root, "owner-file")
    with open(path, "w") as handle:
        handle.write(OWNER_FILE_TEXT)
    context.owner_file = path
    return path


def _python_snippet(context, code):
    return world.run(context, [sys.executable, "-c", code])


# --- Given -----------------------------------------------------------------

@given("the state of the repository is recorded")
def step_record_state(context):
    """Remember every file, hook, policy and setting an installer could change."""
    context.recorded = _snapshot(context)


@given('the repository has its own "{hook}" hook')
def step_own_hook(context, hook):
    """An executable hook written by the repository owner (it exits with 7)."""
    path = os.path.join(_common_dir(context), "hooks", hook)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(OWNER_HOOK)
    os.chmod(path, 0o755)


@given('the repository has its own "{hook}" hook that is not executable')
def step_own_disabled_hook(context, hook):
    """A hook written by the owner and switched off by clearing its mode bits."""
    step_own_hook(context, hook)
    os.chmod(os.path.join(_common_dir(context), "hooks", hook), 0o644)


@given('the repository has an untracked owner file "{name}"')
def step_untracked_owner_file(context, name):
    """A file in the working tree that is the owner's and must stay as written."""
    world.write_file(context, name, "owner policy must remain unchanged\n")


@given('the repository has a checker policy "{name}" that always passes')
def step_passing_policy(context, name):
    """A root policy file with one command checker that always succeeds."""
    world.write_file(
        context, name,
        "version: 1\ncheckers:\n  - type: command\n    command: /usr/bin/true\n",
    )


@given('git is configured with core.hooksPath "{value}"')
def step_hooks_path(context, value):
    """A repository-level hooks path, as a hook manager would set it."""
    world.git(context, "config", "core.hooksPath", value)


@given("git is configured with an empty core.hooksPath")
def step_empty_hooks_path(context):
    """A hooks path that is set but empty is still a configured hook setup."""
    world.git(context, "config", "core.hooksPath", "")


@given('a global git configuration sets core.hooksPath to "{value}"')
def step_global_hooks_path(context, value):
    """The user's global git configuration redirects hooks for every repository."""
    path = os.path.join(context.root, "global.gitconfig")
    with open(path, "w") as handle:
        handle.write("[core]\n\thooksPath = %s\n" % value)
    context.env["GIT_CONFIG_GLOBAL"] = path
    context.global_config = (path, _read(path))


@given('a linked worktree "{name}" of the repository')
def step_linked_worktree(context, name):
    """A second working directory sharing the repository's Git directory."""
    path = os.path.join(context.root, name)
    world.git(context, "worktree", "add", "-q", "-b", name, path)
    context.main_repo = context.repo
    context.worktree = path


@given('I work from the linked worktree "{name}"')
def step_work_from_worktree(context, name):
    """Run later steps from the linked worktree instead of the main directory."""
    context.repo = os.path.join(context.root, name)


@given("the managed local {part} has been edited by its owner")
def step_edit_managed(context, part):
    """Append a line to one file of the installed local gate."""
    with open(_gate_path(context, part), "ab") as handle:
        handle.write(b"# owner addition\n")


@given("the managed receipt hook has been edited by its owner")
def step_edit_receipt_hook(context):
    """Append a line to the installed commit-msg hook."""
    with open(_gate_path(context, "commit-msg hook", RECEIPT_PARTS), "ab") as handle:
        handle.write(b"# owner addition\n")


@given("the managed receipt hook has been disabled")
def step_disable_receipt_hook(context):
    """Clear the executable bits of the installed commit-msg hook."""
    os.chmod(_gate_path(context, "commit-msg hook", RECEIPT_PARTS), 0o644)


@given("the managed pre-commit hook has been disabled")
def step_disable_hook(context):
    """Clear the executable bits of the installed pre-commit hook."""
    os.chmod(_gate_path(context, "hook"), 0o644)


@given("the managed local {part} is a symlink to a file of the owner")
def step_symlink_local(context, part):
    """Replace one managed file with a symlink to an unrelated file of the owner."""
    path = _gate_path(context, part)
    target = _owner_file(context)
    os.unlink(path)
    os.symlink(target, path)


@given("an unmanaged local policy exists without any managed hook")
def step_unmanaged_policy(context):
    """A policy.json in the LeftBlock directory that LeftBlock did not write."""
    directory = os.path.join(_common_dir(context), "leftblock")
    os.makedirs(directory)
    context.owner_file = os.path.join(directory, "policy.json")
    with open(context.owner_file, "w") as handle:
        handle.write(OWNER_FILE_TEXT)


@given("the receipt-mode {part} is a symlink to a file of the owner")
def step_symlink_receipt(context, part):
    """Replace the commit-msg hook or its ownership state with a symlink."""
    path = _gate_path(context, part, RECEIPT_PARTS)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    target = _owner_file(context)
    os.symlink(target, path)


@given("the commit-msg hook slot holds a directory")
def step_hook_directory(context):
    """Something that is not a file sits where the commit-msg hook belongs."""
    path = _gate_path(context, "commit-msg hook", RECEIPT_PARTS)
    os.makedirs(path)


@given("the git hooks directory is a symlink to another directory")
def step_hooks_dir_symlink(context):
    """The repository's hooks directory has been replaced by a symlink."""
    hooks = os.path.join(_common_dir(context), "hooks")
    original = os.path.join(_common_dir(context), "original-hooks")
    os.rename(hooks, original)
    os.symlink(original, hooks, target_is_directory=True)


@given("the receipt-mode ownership state is overwritten with {content}")
def step_malformed_state(context, content):
    """Replace the receipt-mode ownership state with unusable content."""
    with open(_gate_path(context, "ownership state", RECEIPT_PARTS), "w") as handle:
        handle.write(content)


# --- When ------------------------------------------------------------------

@when("I install the local gate")
def step_install_local(context):
    """Run ``leftblock install --local --check-only`` with the available scanner."""
    context.result = world.leftblock(
        context, "install", "--local", "--check-only", "--gitleaks", world.gitleaks_path(),
    )


@when('I install the local gate with the scanner "{scanner}"')
def step_install_local_scanner(context, scanner):
    """The same installation, naming a scanner executable explicitly."""
    context.result = world.leftblock(
        context, "install", "--local", "--check-only", "--gitleaks", scanner,
    )


@when("I install receipt mode answering yes to every question")
def step_install_receipt_yes(context):
    """Plain ``leftblock install`` with a ``y`` waiting on standard input."""
    context.result = world.leftblock(context, "install", stdin="y\n")


@when('I reinstall receipt mode with "{extra}" first on the PATH')
def step_reinstall_receipt_path(context, extra):
    """Plain ``leftblock install`` from a shell whose PATH starts with ``extra``."""
    original = context.env["PATH"]
    context.env["PATH"] = extra + os.pathsep + original
    try:
        context.result = world.leftblock(context, "install")
    finally:
        context.env["PATH"] = original


@when("I install receipt mode from a Python environment without LeftBlock")
def step_install_receipt_no_runtime(context):
    """Run the installer in a process whose interpreter cannot run LeftBlock."""
    broken = shutil.which("false") or "/usr/bin/false"
    context.result = _python_snippet(
        context,
        "import sys; sys.executable = %r; sys.argv = ['leftblock', 'install']; "
        "from leftblock import cli; cli.main()" % broken,
    )


@when("I run the commit-msg hook on a new message with a minimal PATH")
def step_run_commit_msg_hook(context):
    """Run the installed hook directly, as Git would, under ``/usr/bin:/bin``."""
    context.message_file = os.path.join(context.root, "message.txt")
    with open(context.message_file, "w") as handle:
        handle.write("test: synthetic\n")
    env = dict(context.env, PATH="/usr/bin:/bin")
    saved = context.env
    context.env = env
    try:
        context.result = world.run(
            context, [_gate_path(context, "commit-msg hook", RECEIPT_PARTS), context.message_file],
        )
    finally:
        context.env = saved


# --- Then: what the local install wrote ------------------------------------

@then("the local gate is stored in the common git directory only")
def step_gate_in_git_dir(context):
    """Hook, policy, rules and ownership state exist under the Git directory."""
    gitdir = _common_dir(context)
    for part in LOCAL_PARTS:
        path = _gate_path(context, part)
        assert os.path.isfile(path), "missing " + part
        assert os.path.abspath(path).startswith(os.path.abspath(gitdir) + os.sep)


@then("the pre-commit hook is executable")
def step_hook_executable(context):
    """The installed pre-commit hook has the executable bits set."""
    assert _mode(_gate_path(context, "hook")) & stat.S_IXUSR


@then("the policy, rules and ownership state are private to their owner")
def step_private_files(context):
    """Policy, rules and state are mode 0600."""
    for part in ("policy", "rules", "state"):
        assert _mode(_gate_path(context, part)) == 0o600, part


@then("the hook runs LeftBlock in isolated mode against the stored policy")
def step_hook_isolated(context):
    """The hook ignores the environment and the working tree when it runs the check."""
    text = _read(_gate_path(context, "hook")).decode()
    assert "-I -B -m leftblock.cli check --config" in text, text
    assert _gate_path(context, "policy") in text, text


@then("the recorded ownership matches the installed policy")
def step_ownership_matches(context):
    """The ownership state carries the digest of the policy that is installed."""
    state = json.loads(_read(_gate_path(context, "state")))
    digest = hashlib.sha256(_read(_gate_path(context, "policy"))).hexdigest()
    assert state["policy_sha256"] == digest


@then("no signing secret has been created")
def step_no_secret(context):
    """The signing-secret path does not exist."""
    assert not os.path.exists(context.secret_path), "a signing secret was created"


@then("no pre-commit hook is installed")
def step_no_pre_commit(context):
    """There is no pre-commit hook in the repository."""
    assert not os.path.lexists(_gate_path(context, "hook"))


@then("LeftBlock has created no policy directory")
def step_no_policy_dir(context):
    """The Git directory has no LeftBlock policy directory."""
    assert not os.path.lexists(os.path.join(_common_dir(context), "leftblock"))


@then("LeftBlock has written no default policy files")
def step_no_defaults(context):
    """Neither .leftblock.yml nor .leftblock/ exists in the working tree."""
    for name in (".leftblock.yml", ".leftblock"):
        assert not os.path.exists(os.path.join(context.repo, name)), name


@then("nothing in the repository has changed since it was recorded")
def step_nothing_changed(context):
    """Working tree, hooks, policy, settings and status match the recording."""
    tree, git = _snapshot(context)
    before_tree, before_git = context.recorded
    assert tree == before_tree, "the working tree changed"
    assert git == before_git, "hooks, policy or settings changed"


@then("the working tree is as it was recorded")
def step_tree_unchanged(context):
    """No tracked or untracked file was added, removed or edited."""
    tree, git = _snapshot(context)
    assert tree == context.recorded[0], "the working tree changed"
    assert git["status"] == context.recorded[1]["status"], "git status changed"


@then('the owner\'s "{hook}" hook is as the owner wrote it')
def step_own_hook_intact(context, hook):
    """The owner's hook still has its original content."""
    assert _read(os.path.join(_common_dir(context), "hooks", hook)).decode() == OWNER_HOOK


@then("the owner's file is untouched")
def step_owner_file_intact(context):
    """The file the owner pointed a symlink at, or wrote, still holds its content."""
    assert _read(context.owner_file).decode() == OWNER_FILE_TEXT


@then("the global git configuration is untouched")
def step_global_intact(context):
    """The global configuration file is byte-for-byte what it was."""
    path, content = context.global_config
    assert _read(path) == content


# --- Then: linked worktrees -------------------------------------------------

@then("the pre-commit hook lives in the main repository's git directory")
def step_hook_in_main(context):
    """The gate was written once, to the Git directory all worktrees share."""
    assert os.path.isfile(os.path.join(context.main_repo, ".git", "hooks", "pre-commit"))
    private = world.run(context, ["git", "rev-parse", "--path-format=absolute", "--git-dir"])
    assert not os.path.exists(os.path.join(private.stdout.strip(), "hooks", "pre-commit"))


@then("the linked worktree has no LeftBlock policy file")
def step_worktree_no_policy(context):
    """No tracked policy appears in the linked worktree."""
    assert not os.path.exists(os.path.join(context.worktree, ".leftblock.yml"))


# --- Then: receipt-mode installation ---------------------------------------

@then("the commit-msg hook and its ownership state are installed")
def step_receipt_installed(context):
    """Both files exist as regular files in the hooks directory."""
    for part in RECEIPT_PARTS:
        assert os.path.isfile(_gate_path(context, part, RECEIPT_PARTS)), part


@then("no commit-msg hook or ownership state is installed")
def step_receipt_absent(context):
    """Neither receipt-mode file exists."""
    for part in RECEIPT_PARTS:
        assert not os.path.lexists(_gate_path(context, part, RECEIPT_PARTS)), part


@then("default policy files are written to the working tree")
def step_defaults_written(context):
    """Receipt mode writes .leftblock.yml and the .leftblock rules directory."""
    assert os.path.isfile(os.path.join(context.repo, ".leftblock.yml"))
    assert os.path.isdir(os.path.join(context.repo, ".leftblock"))


@then("a signing secret exists that only its owner can read")
def step_secret_private(context):
    """The secret file exists with mode 0600."""
    assert os.path.isfile(context.secret_path)
    assert _mode(context.secret_path) == 0o600


@then("the commit-msg hook runs LeftBlock with the installing interpreter")
def step_receipt_interpreter(context):
    """The hook pins the Python that installed it."""
    text = _read(_gate_path(context, "commit-msg hook", RECEIPT_PARTS)).decode()
    assert "exec %s -m leftblock.cli hook" % shlex.quote(sys.executable) in text, text


@then("the commit-msg hook captures the PATH of the installation")
def step_receipt_captures_path(context):
    """The hook exports the installing shell's PATH for its checkers."""
    text = _read(_gate_path(context, "commit-msg hook", RECEIPT_PARTS)).decode()
    assert "export PATH=%s:" % shlex.quote(context.env["PATH"]) in text, text


@then('the commit-msg hook captures a PATH that starts with "{extra}"')
def step_receipt_path_refreshed(context, extra):
    """A reinstall refreshed the captured PATH."""
    text = _read(_gate_path(context, "commit-msg hook", RECEIPT_PARTS)).decode()
    assert "export PATH=%s:" % extra in text, text


@then("the commit-msg hook is executable and its ownership state is private")
def step_receipt_modes(context):
    """Hook mode 0755, ownership state mode 0600."""
    assert _mode(_gate_path(context, "commit-msg hook", RECEIPT_PARTS)) == 0o755
    assert _mode(_gate_path(context, "ownership state", RECEIPT_PARTS)) == 0o600


@then("the recorded ownership matches the installed commit-msg hook")
def step_receipt_ownership(context):
    """The ownership state carries the digest of the hook on disk."""
    state = json.loads(_read(_gate_path(context, "ownership state", RECEIPT_PARTS)))
    digest = hashlib.sha256(_read(_gate_path(context, "commit-msg hook", RECEIPT_PARTS))).hexdigest()
    assert state["sha256"] == digest


@then("the message file carries a clean inspection receipt")
def step_message_receipt(context):
    """The hook stamped the message file with a clean receipt."""
    with open(context.message_file) as handle:
        assert "Inspection-result: clean" in handle.read()
