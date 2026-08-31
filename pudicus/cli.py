import argparse
import sys
import os
import json
import subprocess
import shlex
from datetime import datetime, timezone
from pudicus.core import (
    get_secret, compute_hmac, get_tree_hash, get_commit_tree_hash,
    load_config, execute_checkers, get_trailer, run_cmd, SECRET_FILE_DEFAULT
)

def print_info(msg):
    print(f"\033[1;34m[pudicus]\033[0m {msg}", file=sys.stderr)

def print_warn(msg):
    print(f"\033[1;33m[pudicus]\033[0m {msg}", file=sys.stderr)

def print_err(msg):
    print(f"\033[1;31m[pudicus ERROR]\033[0m {msg}", file=sys.stderr)

def cmd_install(args):
    """Setup the git hook and secret."""
    # A linked worktree has a `.git` *file*, not a `.git/hooks` directory.
    # Hooks are shared through the repository's common Git directory, so resolve
    # that directory through Git instead of constructing a path from repo_root.
    git_common_dir = run_cmd(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"]
    ).stdout.strip()
    hook_dir = os.path.join(git_common_dir, "hooks")
    os.makedirs(hook_dir, exist_ok=True)
    hook_path = os.path.join(hook_dir, "commit-msg")
    
    if os.path.exists(hook_path):
        print_warn(f"Hook already exists at {hook_path}. Overwrite? [y/N]")
        if input().lower() != 'y':
            print_info("Skipped hook installation.")
            return

    # Git invokes hooks with a deliberately minimal PATH.  Pin the Python
    # interpreter that installed Pudicus and retain the install-time PATH so
    # command checkers (for example Homebrew's gitleaks) remain discoverable.
    # Re-run `pudicus install` after moving the environment or checker binary.
    install_path = os.environ.get("PATH", "")
    python_executable = sys.executable
    hook_script = f"""#!/usr/bin/env bash
# Pudicus commit-msg hook
# Installed Python: {python_executable}
# PATH captured at installation time for configured command checkers.
export PATH={shlex.quote(install_path)}:${{PATH:-}}
exec {shlex.quote(python_executable)} -m pudicus.cli hook "$1"
"""
    with open(hook_path, 'w') as f:
        f.write(hook_script)
    os.chmod(hook_path, 0o755)
    print_info(f"Installed git hook at {hook_path}")

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

def cmd_hook(args):
    """Run checkers on staged files and sign the commit."""
    repo_root = run_cmd(["git", "rev-parse", "--show-toplevel"]).stdout.strip()
    config = load_config(repo_root)
    
    if not config or 'checkers' not in config:
        print_warn("No .pudicus.yml found or no checkers defined. Skipping inspection.")
        sys.exit(0)
    
    try:
        secret = get_secret()
    except FileNotFoundError:
        print_err("Shared secret not found. Run 'pudicus install' first.")
        sys.exit(1)

    tree_hash = get_tree_hash()
    print_info(f"Scanning tree {tree_hash}...")
    
    results = execute_checkers(config['checkers'])
    
    all_clean = True
    failed_checkers = []
    for res in results:
        if not res.clean:
            all_clean = False
            failed_checkers.append(res)
            
    validator_str = f"pudicus-v{config.get('version', '1')}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    if all_clean:
        result_str = "clean"
        print_info("✓ All checks passed.")
    else:
        print_warn(f"✗ Found issues in {len(failed_checkers)} checker(s):")
        for res in failed_checkers:
            print_warn(f"  - {res.name}:")
            if isinstance(res.findings, list):
                for f in res.findings:
                    desc = f.get('Description', 'Unknown')
                    path = f.get('File', 'Unknown')
                    print(f"      File: {path} -> {desc}", file=sys.stderr)
            else:
                print(f"      {res.findings}", file=sys.stderr)
                
        if not sys.stdin.isatty():
            print_err("Findings require human approval but no interactive terminal is available. Commit blocked.")
            sys.exit(1)
            
        print_warn("Commit will be blocked unless you approve these findings.")
        password = input(f"\033[1m[pudicus]\033[0m Enter approval passphrase to override: ").strip()
        
        if password != secret:
            print_err("Incorrect passphrase. Commit blocked.")
            sys.exit(1)
            
        result_str = f"override:{len(failed_checkers)}-checkers"
        print_info("✓ Override approved.")

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
        print_err("Shared secret not found. Run 'pudicus install'.")
        sys.exit(1)
        
    range_str = args.range
    if ".." in range_str:
        commits = run_cmd(["git", "rev-list", "--reverse", range_str]).stdout.splitlines()
    else:
        commits = [run_cmd(["git", "rev-parse", range_str]).stdout.strip()]
        
    if not commits:
        print_info("No commits found in range.")
        sys.exit(0)
        
    config = load_config(repo_root)
    if not config or 'checkers' not in config:
        print_err("No .pudicus.yml found.")
        sys.exit(1)
        
    validator_str = f"pudicus-v{config.get('version', '1')}"
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
                
            results = execute_checkers(config['checkers'], cwd=wt_dir)
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
            if not sys.stdin.isatty():
                print_err("Findings require human approval but no interactive terminal is available. Approval blocked.")
                sys.exit(1)
                
            password = input(f"\033[1m[pudicus]\033[0m Enter approval passphrase to override for {short}: ").strip()
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
    commit_msg = "chore: retroactive pudicus approval\n"
    cmd = ["git", "commit", "--allow-empty", "-F", "-"] + trailers
    proc = subprocess.run(cmd, input=commit_msg, text=True, capture_output=True, check=True)
    print_info(f"Created approval commit:\n{proc.stdout.strip()}")

def cmd_verify(args):
    """Verify signatures for a commit range."""
    try:
        secret = get_secret()
    except FileNotFoundError:
        print_err("Shared secret not found. Run 'pudicus install'.")
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
    parser = argparse.ArgumentParser(description="Pudicus - A pluggable inspection gate for Git commits")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    install_p = subparsers.add_parser("install", help="Install the commit-msg hook and setup secrets")
    
    hook_p = subparsers.add_parser("hook", help="Run checkers (used internally by git hook)")
    hook_p.add_argument("commit_msg_file", help="Path to the commit message file")
    
    verify_p = subparsers.add_parser("verify", help="Verify commits")
    verify_p.add_argument("range", nargs="?", default="HEAD", help="Commit range (e.g. HEAD~3..HEAD)")
    
    approve_p = subparsers.add_parser("approve", help="Retroactively approve commits")
    approve_p.add_argument("range", help="Commit range to approve")
    
    args = parser.parse_args()
    
    if args.command == "install":
        cmd_install(args)
    elif args.command == "hook":
        cmd_hook(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "approve":
        cmd_approve(args)

if __name__ == "__main__":
    main()
