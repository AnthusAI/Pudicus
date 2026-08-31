import argparse
import sys
import os
import json
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
    repo_root = run_cmd(["git", "rev-parse", "--show-toplevel"]).stdout.strip()
    hook_path = os.path.join(repo_root, ".git", "hooks", "commit-msg")
    
    if os.path.exists(hook_path):
        print_warn(f"Hook already exists at {hook_path}. Overwrite? [y/N]")
        if input().lower() != 'y':
            print_info("Skipped hook installation.")
            return

    # Install the wrapper that calls pudicus hook
    hook_script = f"""#!/usr/bin/env bash
# Pudicus commit-msg hook
pudicus hook "$1"
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
        commits = [range_str]
        
    failures = 0
    for sha in commits:
        short = sha[:7]
        sig = get_trailer(sha, "Inspection-sig")
        claimed_tree = get_trailer(sha, "Inspection-tree")
        validator = get_trailer(sha, "Inspected-by")
        result = get_trailer(sha, "Inspection-result")
        timestamp = get_trailer(sha, "Inspection-at")
        
        if not sig:
            print_err(f"{short}: No Inspection-sig trailer. Commit is unsigned.")
            failures += 1
            continue
            
        if not all([claimed_tree, validator, result, timestamp]):
            print_err(f"{short}: Incomplete inspection trailers.")
            failures += 1
            continue
            
        actual_tree = get_commit_tree_hash(sha)
        if claimed_tree != actual_tree:
            print_err(f"{short}: Tree hash mismatch. Claimed {claimed_tree[:12]}, actual {actual_tree[:12]}.")
            failures += 1
            continue
            
        expected_sig = f"hmac-sha256:{compute_hmac(claimed_tree, validator, result, timestamp, secret)}"
        if sig != expected_sig:
            print_err(f"{short}: Signature mismatch. Receipt is invalid or tampered with.")
            failures += 1
            continue
            
        subject = run_cmd(["git", "log", "-1", sha, "--format=%s"]).stdout.strip()[:50]
        print(f"\033[1;32mPASS:\033[0m {short}: {subject} [{result}]")
        
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
    
    args = parser.parse_args()
    
    if args.command == "install":
        cmd_install(args)
    elif args.command == "hook":
        cmd_hook(args)
    elif args.command == "verify":
        cmd_verify(args)

if __name__ == "__main__":
    main()
