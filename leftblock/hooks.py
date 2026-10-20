"""Install only Pudicus-owned hooks without replacing a project's hook setup."""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile


STATE_NAME = ".pudicus-commit-msg.json"
HOOK_MARKER = "# Pudicus managed commit-msg hook v1\n"
MANUAL_INTEGRATION = (
    'Keep the existing hook setup and compose `leftblock check` into its pre-commit '
    'hook, or `leftblock hook "$1"` into its commit-msg hook, propagating failures.'
)


def _git(repo_root, *args):
    return subprocess.run(
        ["git", *args], cwd=repo_root, text=True, capture_output=True, check=False
    )


def _regular_file(path):
    """Reject symlinks, directories, devices, and other non-regular targets."""
    if os.path.lexists(path) and not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Hook or ownership state is not a regular file. " + MANUAL_INTEGRATION)


def _destination(repo_root, hook_name="commit-msg", state_name=STATE_NAME):
    configured = _git(repo_root, "config", "--get-all", "core.hooksPath")
    if configured.returncode == 0:
        raise ValueError("core.hooksPath is configured; no hooks changed. " + MANUAL_INTEGRATION)
    if configured.returncode != 1:
        raise ValueError("Could not inspect Git hook configuration; no hooks changed.")
    common = _git(repo_root, "rev-parse", "--path-format=absolute", "--git-common-dir")
    if common.returncode or not common.stdout.strip():
        raise ValueError("Could not locate the repository's common Git directory.")
    hook_dir = Path(common.stdout.strip()) / "hooks"
    if os.path.lexists(hook_dir) and (
        hook_dir.is_symlink() or not hook_dir.is_dir()
    ):
        raise ValueError("The hooks directory is not a regular directory. " + MANUAL_INTEGRATION)
    return hook_dir / hook_name, hook_dir / state_name


def _check_ownership(hook, state):
    _regular_file(hook)
    _regular_file(state)
    if not hook.exists() and not state.exists():
        return None
    if not hook.exists() or not state.exists():
        raise ValueError("An existing hook or ownership state is unmanaged. " + MANUAL_INTEGRATION)
    try:
        metadata = json.loads(state.read_text())
        digest = metadata["sha256"]
        valid_state = (
            metadata["version"] == 1
            and metadata["hook"] == "commit-msg"
            and isinstance(digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
        )
    except (ValueError, KeyError, TypeError):
        valid_state = False
    data = hook.read_bytes()
    if not valid_state or (
        HOOK_MARKER.encode() not in data.splitlines(keepends=True)[:3]
        or hashlib.sha256(data).hexdigest() != digest
    ):
        raise ValueError("The existing hook was changed or is not managed by Pudicus. " + MANUAL_INTEGRATION)
    if not hook.stat().st_mode & stat.S_IXUSR:
        raise ValueError("The existing Pudicus hook was disabled; no hooks changed. " + MANUAL_INTEGRATION)
    return data


def validate_hook_install(repo_root):
    """Read-only preflight; raise instead of touching another hook setup."""
    hook, state = _destination(repo_root)
    _check_ownership(hook, state)
    return hook


def _hook_script():
    # Pin the installer environment so noninteractive Git does not need an
    # activated virtualenv. Captured PATH keeps the configured scanner visible.
    return (
        "#!/bin/sh\n"
        + HOOK_MARKER
        + "# PATH captured at installation time for configured command checkers.\n"
        + "export PATH=" + shlex.quote(os.environ.get("PATH", "")) + ":${PATH:-}\n"
        + "exec " + shlex.quote(sys.executable) + ' -m leftblock.cli hook "$1"\n'
    ).encode()


def _replace_file(path, data, mode):
    fd, temporary = tempfile.mkstemp(prefix=".pudicus-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fchmod(output.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install_hook(repo_root):
    """Install or refresh an unchanged managed hook; never prompt to overwrite.

    Hook managers, configured hooks paths, legacy hooks, and owner edits require
    explicit composition by the project. Ownership state is local Git metadata,
    not a security boundary against a user who can change the hook itself.
    """
    hook, state = _destination(repo_root)
    previous = _check_ownership(hook, state)
    runtime = subprocess.run(
        [sys.executable, "-B", "-m", "leftblock.cli", "hook", "--help"],
        cwd=repo_root, text=True, capture_output=True, check=False,
    )
    if runtime.returncode:
        raise ValueError("Install LeftBlock in this Python environment before installing its hook.")
    data = _hook_script()
    if previous == data:
        return True
    hook.parent.mkdir(parents=True, exist_ok=True)
    # Recheck immediately before writing to catch changes during installation.
    if _check_ownership(hook, state) != previous:
        raise ValueError("Hook changed during installation; no hooks changed.")
    if previous is None:
        # Exclusive creation also preserves a hook created after preflight.
        fd = os.open(str(hook), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            os.fchmod(output.fileno(), 0o755)
    else:
        _replace_file(hook, data, 0o755)
    metadata = {
        "version": 1,
        "hook": "commit-msg",
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    _replace_file(state, (json.dumps(metadata, sort_keys=True) + "\n").encode(), 0o600)
    return True


LOCAL_STATE_NAME = ".leftblock-pre-commit.json"
LOCAL_HOOK_MARKER = "# LeftBlock managed local pre-commit hook v1\n"


def _local_paths(repo_root):
    hook, state = _destination(repo_root, "pre-commit", LOCAL_STATE_NAME)
    policy_dir = hook.parent.parent / "leftblock"
    if os.path.lexists(policy_dir) and (
        policy_dir.is_symlink() or not policy_dir.is_dir()
    ):
        raise ValueError("The local policy directory is not a regular directory.")
    return {
        "hook": hook,
        "state": state,
        "policy": policy_dir / "policy.json",
        "rules": policy_dir / "gitleaks.toml",
    }


def _local_owned_contents(paths):
    for path in paths.values():
        _regular_file(path)
    if not any(path.exists() for path in paths.values()):
        return {name: None for name in paths}
    if not all(path.exists() for path in paths.values()):
        raise ValueError("Existing local pre-commit hook or policy is unmanaged; no files changed.")
    contents = {name: path.read_bytes() for name, path in paths.items()}
    try:
        state = json.loads(contents["state"])
        valid = state["version"] == 1 and state["hook"] == "pre-commit"
        for name, key in (("hook", "sha256"), ("policy", "policy_sha256"), ("rules", "rules_sha256")):
            valid = valid and state[key] == hashlib.sha256(contents[name]).hexdigest()
    except (ValueError, TypeError, KeyError):
        valid = False
    if (
        not valid
        or LOCAL_HOOK_MARKER.encode() not in contents["hook"].splitlines(keepends=True)[:3]
        or not paths["hook"].stat().st_mode & stat.S_IXUSR
    ):
        raise ValueError("Existing local hook or policy was edited or disabled; no files changed.")
    return contents


def validate_local_check_install(repo_root):
    """Read-only preflight for the opt-in, secret-free local pre-commit gate."""
    paths = _local_paths(repo_root)
    _local_owned_contents(paths)
    return paths


def _local_bundle(paths, gitleaks=None):
    binary = shutil.which(gitleaks or "gitleaks")
    if not binary or not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        raise ValueError("An existing executable Gitleaks installation is required.")
    runtime = subprocess.run(
        [sys.executable, "-I", "-B", "-m", "leftblock.cli", "check", "--help"],
        text=True, capture_output=True, check=False,
    )
    if runtime.returncode or "--config" not in runtime.stdout:
        raise ValueError("Install LeftBlock with local policy support in this Python environment first.")
    binary = os.path.abspath(binary)
    rules = (Path(__file__).resolve().parent / "data" / "gitleaks.toml").read_bytes()
    command = [
        binary, "protect", "--staged", "--config", str(paths["rules"]),
        "--redact", "--no-banner", "--report-format", "json",
        "--report-path", "{report_file}",
    ]
    policy = {
        "version": 1,
        "checkers": [{
            "name": "gitleaks", "type": "command",
            "command": " ".join(shlex.quote(arg) for arg in command),
            "success_codes": [0], "finding_codes": [1],
        }],
    }
    # -I ignores PYTHONPATH and the repository's current directory. The
    # installing Python must have LeftBlock installed in its own environment.
    hook = (
        "#!/bin/sh\n" + LOCAL_HOOK_MARKER
        + "export PATH=" + shlex.quote(os.environ.get("PATH", "")) + ":${PATH:-}\n"
        + "exec " + shlex.quote(sys.executable)
        + " -I -B -m leftblock.cli check --config " + shlex.quote(str(paths["policy"])) + "\n"
    ).encode()
    bundle = {
        "hook": hook,
        "policy": (json.dumps(policy, indent=2) + "\n").encode(),
        "rules": rules,
    }
    state = {
        "version": 1, "hook": "pre-commit",
        "sha256": hashlib.sha256(hook).hexdigest(),
        "policy_sha256": hashlib.sha256(bundle["policy"]).hexdigest(),
        "rules_sha256": hashlib.sha256(rules).hexdigest(),
    }
    bundle["state"] = (json.dumps(state, sort_keys=True) + "\n").encode()
    return bundle


def install_local_check_hook(repo_root, gitleaks=None):
    """Install a fixed Gitleaks baseline without tracked policy or credentials.

    The pre-commit slot is independent of existing commit-msg receipts. An
    existing root policy is not executed or changed by this opt-in local mode.
    """
    paths = validate_local_check_install(repo_root)
    previous = _local_owned_contents(paths)
    desired = _local_bundle(paths, gitleaks)
    if previous == desired:
        return True
    created_dirs = []
    written = []
    try:
        for directory in (paths["hook"].parent, paths["policy"].parent):
            if not directory.exists():
                directory.mkdir()
                created_dirs.append(directory)
        # Activate the hook last. Rollback only our own unchanged writes if any
        # step fails; never remove an edit made concurrently by another process.
        for name in ("rules", "policy", "state", "hook"):
            path = paths[name]
            _regular_file(path)
            current = path.read_bytes() if path.exists() else None
            if current != previous[name]:
                raise ValueError("Local hook or policy changed during installation.")
            mode = 0o755 if name == "hook" else 0o600
            if previous[name] is None:
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
                with os.fdopen(fd, "wb") as output:
                    output.write(desired[name])
                    os.fchmod(output.fileno(), mode)
            else:
                _replace_file(path, desired[name], mode)
            written.append(name)
        return True
    except BaseException:
        for name in reversed(written):
            path = paths[name]
            if path.is_file() and not path.is_symlink() and path.read_bytes() == desired[name]:
                if previous[name] is None:
                    path.unlink()
                else:
                    _replace_file(path, previous[name], 0o755 if name == "hook" else 0o600)
        for directory in reversed(created_dirs):
            if directory.is_dir() and not any(directory.iterdir()):
                directory.rmdir()
        raise
