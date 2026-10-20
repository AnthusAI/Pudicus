import argparse
import sys
import os
import json
import subprocess
import getpass
import shlex
import yaml
from datetime import datetime, timezone
from leftblock.merge import (
    MergeScopeError, build_scoped_index, checker_environment, index_entries, merge_state,
)
from leftblock import allow as allowlist
from leftblock.core import (
    get_secret, compute_hmac, get_tree_hash, get_commit_tree_hash,
    load_config, validate_checkers, execute_checkers, get_trailer, run_cmd, SECRET_FILE_DEFAULT,
    CheckerResult,
)

def print_info(msg):
    print(f"\033[1;34m[leftblock]\033[0m {msg}", file=sys.stderr)

def print_warn(msg):
    print(f"\033[1;33m[leftblock]\033[0m {msg}", file=sys.stderr)

def print_err(msg):
    print(f"\033[1;31m[leftblock ERROR]\033[0m {msg}", file=sys.stderr)

DEFAULT_LEFTBLOCK_YML = """\
version: 1
checkers:
  - name: gitleaks
    type: command
    command: gitleaks protect --staged --config .leftblock/gitleaks.toml --redact --no-banner --report-format json --report-path {report_file}
    success_codes: [0]
    finding_codes: [1]
"""

def write_default_configs(repo_root):
    """Install the zero-config defaults into a repo.

    Writes a default .leftblock.yml (pointing at the shipped gitleaks
    ruleset) and copies the packaged gitleaks.toml into
    <repo>/.leftblock/. Existing files are never overwritten.
    """
    config_dir = os.path.join(repo_root, ".leftblock")
    leftblock_yml = os.path.join(repo_root, ".leftblock.yml")
    ruleset_target = os.path.join(config_dir, "gitleaks.toml")

    if not os.path.exists(leftblock_yml):
        with open(leftblock_yml, "w") as f:
            f.write(DEFAULT_LEFTBLOCK_YML)
        print_info(f"Wrote default checker config at {leftblock_yml}")
    else:
        print_info(f"Existing {leftblock_yml} left untouched.")

    packaged_ruleset = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data", "gitleaks.toml"
    )
    if os.path.exists(packaged_ruleset):
        os.makedirs(config_dir, exist_ok=True)
        if not os.path.exists(ruleset_target):
            import shutil
            shutil.copyfile(packaged_ruleset, ruleset_target)
            print_info(f"Installed shipped gitleaks ruleset at {ruleset_target}")
        else:
            print_info(f"Existing {ruleset_target} left untouched.")
    else:
        print_warn(f"Packaged ruleset missing at {packaged_ruleset}; default gitleaks rules only.")

def cmd_install(args):
    """Setup the git hook and secret."""
    repo_root = run_cmd(
        ["git", "rev-parse", "--show-toplevel"], check=False
    ).stdout.strip()
    if not repo_root:
        print_err("Run installation inside a Git repository.")
        sys.exit(1)
    if getattr(args, "local", False) or getattr(args, "check_only", False):
        if not (args.local and args.check_only):
            print_err("Use --local and --check-only together for a local pre-commit gate.")
            sys.exit(1)
        from leftblock.hooks import install_local_check_hook
        try:
            install_local_check_hook(repo_root, getattr(args, "gitleaks", None))
        except (ValueError, OSError) as exc:
            print_err(str(exc))
            sys.exit(1)
        print_info("Installed local LeftBlock pre-commit gate; no signing secret is needed.")
        return
    if getattr(args, "gitleaks", None):
        print_err("--gitleaks is supported with --local --check-only.")
        sys.exit(1)
    from leftblock.hooks import install_hook
    try:
        install_hook(repo_root)
    except (ValueError, OSError) as exc:
        print_err(str(exc))
        sys.exit(1)
    write_default_configs(repo_root)
    print_info("Installed LeftBlock commit-msg hook.")

    # Generate secret if needed
    secret_dir = os.path.dirname(SECRET_FILE_DEFAULT)
    if not os.path.exists(SECRET_FILE_DEFAULT):
        os.makedirs(secret_dir, exist_ok=True)
        secret = os.urandom(16).hex()
        with open(SECRET_FILE_DEFAULT, 'w') as f:
            f.write(secret)
        os.chmod(SECRET_FILE_DEFAULT, 0o600)
        print_info(f"Generated new shared secret at {SECRET_FILE_DEFAULT}")
    else:
        print_info(f"Shared secret already exists at {SECRET_FILE_DEFAULT}")

def configured_checks(repo_root, config_path=None, overrides=True):
    """Run the checkers, attach override ids and apply staged overrides."""
    config, results = _run_configured_checks(repo_root, config_path)
    allowlist.attach_ids(repo_root, results)
    if not overrides:
        return config, results
    try:
        entries = allowlist.load_allowlist(repo_root)
    except allowlist.AllowError:
        results.append(CheckerResult(
            "leftblock-allow", False,
            "Invalid .leftblock-allow.yml; inspection blocked.", error=True,
        ))
        return config, results
    shown = set()
    for finding, reason in allowlist.apply_allowlist(results, entries):
        # Several matches on one line share an id; report each override once.
        if finding["id"] in shown:
            continue
        shown.add(finding["id"])
        print_info(
            "Override applied: file " + json.dumps(finding["File"], ensure_ascii=True)
            + ", rule " + json.dumps(finding["RuleID"], ensure_ascii=True)
            + ", id " + finding["id"]
            + ", reason " + json.dumps(reason, ensure_ascii=True)
        )
    return config, results


def _run_configured_checks(repo_root, config_path=None):
    try:
        config = load_config(repo_root, config_path)
        checkers = validate_checkers(config)
    except (OSError, ValueError, yaml.YAMLError):
        print_err("Missing or invalid checker configuration. Inspection blocked; review the selected policy.")
        sys.exit(1)
    # Inherited whole files at the same path can be omitted during a merge.
    # Changed/resolved files and renamed paths keep their full staged diff.
    # Any failure to scope falls back to the full staged scan (stricter).
    scoped_index = None
    try:
        base_env = checker_environment()
    except (MergeScopeError, ValueError):
        return config, [CheckerResult(
            "git-environment", False, "Invalid Git checker environment.", error=True,
        )]
    try:
        state = merge_state(repo_root)
        if state:
            scoped_index = build_scoped_index(repo_root, state[1], head=state[0])
            entries = index_entries(repo_root, scoped_index)
            env = checker_environment(scoped_index)
    except (MergeScopeError, OSError, ValueError):
        if scoped_index and os.path.exists(scoped_index):
            os.remove(scoped_index)
        scoped_index = None
    try:
        results = execute_checkers(checkers, cwd=repo_root, env=env if scoped_index else base_env)
        if scoped_index:
            try:
                stable = merge_state(repo_root) == state and index_entries(repo_root, scoped_index) == entries
            except (MergeScopeError, OSError, ValueError):
                stable = False
            if not stable:
                results.append(CheckerResult(
                    "merge-scope", False,
                    "Merge state or inspected index changed during inspection. Retry the check.",
                    error=True,
                ))
        return config, results
    finally:
        if scoped_index and os.path.exists(scoped_index):
            os.remove(scoped_index)


def print_failures(failures):
    for result in failures:
        print_warn(f"Checker {json.dumps(str(result.name))} did not pass.")
        if isinstance(result.findings, list):
            for finding in result.findings:
                print("      " + json.dumps(finding, ensure_ascii=True), file=sys.stderr)
        else:
            print_warn(str(result.findings))


def default_local_policy(repo_root):
    """The local check-only policy file when one is installed, else None."""
    proc = run_cmd(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        check=False, cwd=repo_root,
    )
    if proc.returncode or not proc.stdout.strip():
        return None
    path = os.path.join(proc.stdout.strip(), "leftblock", "policy.json")
    return path if os.path.isfile(path) else None


def print_override_instructions(failures, repo_root, config_path):
    findings = [
        f for result in failures if isinstance(result.findings, list) for f in result.findings
    ]
    ids = [f["id"] for f in findings if f.get("id")]
    if len(ids) < len(findings):
        print_warn("Findings without an id cannot be overridden and must be removed.")
    if not ids:
        return
    command = f"{shlex.quote(sys.executable)} -I -B -m leftblock.cli allow {' '.join(dict.fromkeys(ids))}"
    default = default_local_policy(repo_root) or os.path.join(repo_root, ".leftblock.yml")
    if config_path and os.path.abspath(config_path) != os.path.abspath(default):
        command += f" --config {shlex.quote(config_path)}"
    print_err("Inspection blocked. If a finding is a false alarm, record a reviewed override:")
    print(f"  {command} --reason \"<why this is not sensitive>\"", file=sys.stderr)
    print(
        "This adds the finding to .leftblock-allow.yml and stages it, so the override "
        "appears in the commit and its review.",
        file=sys.stderr,
    )


def cmd_allow(args):
    """Record reviewed overrides for current findings in .leftblock-allow.yml."""
    reason = " ".join(args.reason.split())
    if len(reason) < allowlist.MIN_REASON:
        print_err(f"--reason must explain the override (at least {allowlist.MIN_REASON} characters).")
        sys.exit(1)
    repo_root = run_cmd(["git", "rev-parse", "--show-toplevel"]).stdout.strip()
    config_path = args.config or default_local_policy(repo_root)
    tree_hash = get_tree_hash()
    _, results = configured_checks(repo_root, config_path, overrides=False)
    if get_tree_hash() != tree_hash:
        print_err("Staged tree changed during inspection. Run it again.")
        sys.exit(1)
    if any(result.error for result in results):
        print_err("A checker could not complete. No override recorded.")
        sys.exit(1)
    current = {
        f["id"]: f for result in results if isinstance(result.findings, list)
        for f in result.findings if f.get("id")
    }
    unknown = [i for i in args.ids if i not in current]
    if unknown:
        print_err("Not a current finding id: " + ", ".join(json.dumps(i) for i in unknown))
        sys.exit(1)
    try:
        added = allowlist.record_overrides(
            repo_root, [current[i] for i in dict.fromkeys(args.ids)], reason,
        )
    except (OSError, allowlist.AllowError):
        print_err(f"Existing {allowlist.ALLOW_FILE} is unreadable or invalid; fix it first.")
        sys.exit(1)
    run_cmd(["git", "add", "--", allowlist.ALLOW_FILE], cwd=repo_root)
    for finding in added:
        print_info(f"Recorded override {finding['id']} for {finding['RuleID']} in {finding['File']}.")
    if not added:
        print_info("Those ids were already recorded.")
    print_info(f"{allowlist.ALLOW_FILE} is staged; the commit must include it.")


def cmd_check(args):
    """Noninteractive staged inspection for existing pre-commit hook managers."""
    repo_root = run_cmd(["git", "rev-parse", "--show-toplevel"]).stdout.strip()
    tree_hash = get_tree_hash()
    _, results = configured_checks(repo_root, getattr(args, "config", None))
    if get_tree_hash() != tree_hash:
        print_err("Staged tree changed during inspection. Check blocked; run it again.")
        sys.exit(1)
    failures = [result for result in results if not result.clean]
    if failures:
        print_failures(failures)
        if any(result.error for result in failures) and not any(
            isinstance(result.findings, list) for result in failures
        ):
            print_err("Inspection blocked. A checker could not complete; no override is available.")
        else:
            print_override_instructions(failures, repo_root, getattr(args, "config", None))
        sys.exit(1)
    print_info("All configured checks passed for staged changes.")


def cmd_hook(args):
    """Run checkers on staged files and sign the commit."""
    repo_root = run_cmd(["git", "rev-parse", "--show-toplevel"]).stdout.strip()
    try:
        secret = get_secret()
    except FileNotFoundError:
        print_err("Shared secret not found. Run 'leftblock install' first.")
        sys.exit(1)

    tree_hash = get_tree_hash()
    print_info(f"Scanning tree {tree_hash}...")

    config, results = configured_checks(repo_root)
    if get_tree_hash() != tree_hash:
        print_err("Staged tree changed during inspection. Commit blocked; run the checks again.")
        sys.exit(1)

    all_clean = True
    failed_checkers = []
    for res in results:
        if not res.clean:
            all_clean = False
            failed_checkers.append(res)

    validator_str = f"leftblock-v{config.get('version', '1')}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if all_clean:
        result_str = "clean"
        print_info("✓ All checks passed.")
    else:
        print_warn(f"✗ Found issues in {len(failed_checkers)} checker(s):")
        print_failures(failed_checkers)
        if any(result.error for result in failed_checkers):
            print_err("A checker could not complete. Commit blocked; fix the checker before retrying.")
            sys.exit(1)

        if not sys.stdin.isatty():
            print_err("Findings require human approval but no interactive terminal is available. Commit blocked.")
            sys.exit(1)

        print_warn("Commit will be blocked unless you approve these findings.")
        password = getpass.getpass(f"\033[1m[leftblock]\033[0m Enter approval passphrase to override: ").strip()

        if password != secret:
            print_err("Incorrect passphrase. Commit blocked.")
            sys.exit(1)

        result_str = f"override:{len(failed_checkers)}-checkers"
        print_info("✓ Override approved.")

    if get_tree_hash() != tree_hash:
        print_err("Staged tree changed before signing. Commit blocked; run the checks again.")
        sys.exit(1)
    hmac_sig = compute_hmac(tree_hash, validator_str, result_str, timestamp, secret)

    # Append trailers
    msg_file = args.commit_msg_file
    with open(msg_file, 'r') as f:
        msg_content = f.read()

    proc = subprocess.run(
        ["git", "interpret-trailers",
         f"--trailer=Inspected-by: {validator_str}",
         f"--trailer=Inspection-tree: {tree_hash}",
         f"--trailer=Inspection-result: {result_str}",
         f"--trailer=Inspection-at: {timestamp}",
         f"--trailer=Inspection-sig: hmac-sha256:{hmac_sig}"],
        input=msg_content, text=True, capture_output=True, check=True
    )

    with open(msg_file, 'w') as f:
        f.write(proc.stdout)

    print_info(f"✓ Commit signed: hmac-sha256:{hmac_sig[:16]}...")

def cmd_approve(args):
    """Retroactively approve commits by generating a paperwork commit."""
    repo_root = run_cmd(["git", "rev-parse", "--show-toplevel"]).stdout.strip()

    try:
        secret = get_secret()
    except FileNotFoundError:
        print_err("Shared secret not found. Run 'leftblock install'.")
        sys.exit(1)

    range_str = args.range
    if ".." in range_str:
        commits = run_cmd(["git", "rev-list", "--reverse", range_str]).stdout.splitlines()
    else:
        commits = [run_cmd(["git", "rev-parse", range_str]).stdout.strip()]

    if not commits:
        print_info("No commits found in range.")
        sys.exit(0)

    try:
        config = load_config(repo_root)
        checkers = validate_checkers(config)
    except (OSError, ValueError, yaml.YAMLError):
        print_err("Missing or invalid checker configuration. Approval blocked.")
        sys.exit(1)

    validator_str = f"leftblock-v{config.get('version', '1')}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    trailers = []

    for sha in commits:
        short = sha[:7]
        print_info(f"Checking commit {short}...")
        actual_tree = get_commit_tree_hash(sha)

        # Set up a worktree for the commit
        import tempfile
        wt_dir = tempfile.mkdtemp()
        run_cmd(["git", "worktree", "add", "--detach", wt_dir, sha])

        try:
            # We want to scan the diff introduced by this commit, so we soft reset to its parent.
            parent = run_cmd(["git", "rev-parse", f"{sha}~1"], check=False).stdout.strip()
            if not parent:
                # Root commit
                empty_tree = run_cmd(["git", "hash-object", "-t", "tree", "/dev/null"]).stdout.strip()
                run_cmd(["git", "reset", "--soft", empty_tree], cwd=wt_dir)
            else:
                run_cmd(["git", "reset", "--soft", parent], cwd=wt_dir)

            results = execute_checkers(checkers, cwd=wt_dir)
        finally:
            run_cmd(["git", "worktree", "remove", "-f", wt_dir])

        all_clean = True
        failed_checkers = []
        for res in results:
            if not res.clean:
                all_clean = False
                failed_checkers.append(res)

        if all_clean:
            result_str = "clean"
        else:
            print_warn(f"✗ Found issues in {short} for {len(failed_checkers)} checker(s).")
            if any(result.error for result in failed_checkers):
                print_err("A checker could not complete. Approval blocked.")
                sys.exit(1)
            if not sys.stdin.isatty():
                print_err("Findings require human approval but no interactive terminal is available. Approval blocked.")
                sys.exit(1)

            password = getpass.getpass(f"\033[1m[leftblock]\033[0m Enter approval passphrase to override for {short}: ").strip()
            if password != secret:
                print_err("Incorrect passphrase. Approval blocked.")
                sys.exit(1)
            result_str = f"override:{len(failed_checkers)}-checkers"

        hmac_sig = compute_hmac(actual_tree, validator_str, result_str, timestamp, secret)

        trailers.append(f"--trailer=Inspected-by: {validator_str}")
        trailers.append(f"--trailer=Inspection-tree: {actual_tree}")
        trailers.append(f"--trailer=Inspection-result: {result_str}")
        trailers.append(f"--trailer=Inspection-at: {timestamp}")
        trailers.append(f"--trailer=Inspection-sig: hmac-sha256:{hmac_sig}")

    # Create the approval commit
    commit_msg = "chore: retroactive leftblock approval\n"
    cmd = ["git", "commit", "--allow-empty", "-F", "-"] + trailers
    proc = subprocess.run(cmd, input=commit_msg, text=True, capture_output=True, check=True)
    print_info(f"Created approval commit:\n{proc.stdout.strip()}")

def cmd_verify(args):
    """Verify signatures for a commit range."""
    try:
        secret = get_secret()
    except FileNotFoundError:
        print_err("Shared secret not found. Run 'leftblock install'.")
        sys.exit(1)

    range_str = args.range
    if ".." in range_str:
        commits = run_cmd(["git", "rev-list", range_str]).stdout.splitlines()
    else:
        commits = [run_cmd(["git", "rev-parse", range_str]).stdout.strip()]

    # Pool all valid signatures found in the range
    valid_trees = set()

    for sha in commits:
        # Get all trailers from the commit message
        msg = run_cmd(["git", "log", "-1", sha, "--format=%B"]).stdout
        # Basic parsing of trailers. git log format for multiple identical keys is tricky,
        # so we parse the raw message.
        import re
        trees = re.findall(r"^Inspection-tree:\s*(.+)$", msg, re.MULTILINE)
        sigs = re.findall(r"^Inspection-sig:\s*hmac-sha256:(.+)$", msg, re.MULTILINE)
        validators = re.findall(r"^Inspected-by:\s*(.+)$", msg, re.MULTILINE)
        results = re.findall(r"^Inspection-result:\s*(.+)$", msg, re.MULTILINE)
        timestamps = re.findall(r"^Inspection-at:\s*(.+)$", msg, re.MULTILINE)

        # Zip them up (assuming they appear in blocks)
        for t, s, v, r, ts in zip(trees, sigs, validators, results, timestamps):
            expected = compute_hmac(t, v, r, ts, secret)
            if s == expected:
                valid_trees.add(t)

    failures = 0
    for sha in commits:
        short = sha[:7]
        actual_tree = get_commit_tree_hash(sha)

        if actual_tree not in valid_trees:
            print_err(f"{short}: No valid signature found for tree {actual_tree[:12]}.")
            failures += 1
            continue

        subject = run_cmd(["git", "log", "-1", sha, "--format=%s"]).stdout.strip()[:50]
        print(f"\033[1;32mPASS:\033[0m {short}: {subject} [verified]")

    if failures > 0:
        print_err(f"Verification failed: {failures}/{len(commits)} commit(s) invalid.")
        sys.exit(1)
    else:
        print(f"\033[1;32mAll {len(commits)} commit(s) verified.\033[0m")

def main():
    parser = argparse.ArgumentParser(description="LeftBlock - A pluggable inspection gate for Git commits")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_p = subparsers.add_parser("install", help="Install the commit-msg hook and setup secrets")
    install_p.add_argument("--local", action="store_true", help="Keep policy in the common Git directory (with --check-only)")
    install_p.add_argument("--check-only", action="store_true", help="Install a pre-commit check without signing (with --local)")
    install_p.add_argument("--gitleaks", help="Existing Gitleaks executable for a local check-only installation")

    check_p = subparsers.add_parser("check", help="Inspect staged changes without signing")
    check_p.add_argument("--config", help="Explicit local checker policy; defaults to .leftblock.yml")

    allow_p = subparsers.add_parser("allow", help="Record a reviewed override for current findings")
    allow_p.add_argument("ids", nargs="+", metavar="ID", help="Finding id(s) shown by the blocked check")
    allow_p.add_argument("--reason", required=True, help="Why the finding is not sensitive")
    allow_p.add_argument("--config", help="Checker policy; defaults to the local install policy, else .leftblock.yml")

    hook_p = subparsers.add_parser("hook", help="Run checkers (used internally by git hook)")
    hook_p.add_argument("commit_msg_file", help="Path to the commit message file")

    verify_p = subparsers.add_parser("verify", help="Verify commits")
    verify_p.add_argument("range", nargs="?", default="HEAD", help="Commit range (e.g. HEAD~3..HEAD)")

    approve_p = subparsers.add_parser("approve", help="Retroactively approve commits")
    approve_p.add_argument("range", help="Commit range to approve")

    args = parser.parse_args()

    if args.command == "install":
        cmd_install(args)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "allow":
        cmd_allow(args)
    elif args.command == "hook":
        cmd_hook(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "approve":
        cmd_approve(args)

if __name__ == "__main__":
    main()
