import os
import sys
import subprocess
import hmac
import hashlib
import json
import time
from datetime import datetime
from typing import List, Dict, Any, Tuple
import tempfile
import yaml

SECRET_FILE_DEFAULT = os.path.expanduser("~/.config/pudicus/secret")

def get_secret(secret_path: str = SECRET_FILE_DEFAULT) -> str:
    if not os.path.exists(secret_path):
        raise FileNotFoundError(f"Secret file not found at {secret_path}")
    with open(secret_path, 'r') as f:
        return f.read().strip()

def compute_hmac(tree_hash: str, validator: str, result: str, timestamp: str, secret: str) -> str:
    msg = f"{tree_hash}|{validator}|{result}|{timestamp}".encode('utf-8')
    return hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).hexdigest()

def run_cmd(cmd: List[str], check: bool = True, capture_output: bool = True, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=capture_output, text=True, **kwargs)

def get_tree_hash() -> str:
    return run_cmd(["git", "write-tree"]).stdout.strip()

def get_commit_tree_hash(commit_sha: str) -> str:
    output = run_cmd(["git", "cat-file", "-p", commit_sha]).stdout
    for line in output.splitlines():
        if line.startswith("tree "):
            return line.split(" ")[1].strip()
    return ""

def load_config(repo_root: str) -> Dict[str, Any]:
    config_path = os.path.join(repo_root, ".pudicus.yml")
    if not os.path.exists(config_path):
        return {}
    with open(config_path, 'r') as f:
        return yaml.safe_load(f) or {}

class CheckerResult:
    def __init__(self, name: str, clean: bool, findings: Any = None):
        self.name = name
        self.clean = clean
        self.findings = findings

def run_command_checker(checker: Dict[str, Any]) -> CheckerResult:
    name = checker.get('name', 'unknown')
    cmd = checker.get('command', '')
    success_codes = checker.get('success_codes', [0])
    
    # Replace {report_file} if present
    report_file = None
    if "{report_file}" in cmd:
        fd, report_file = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        cmd = cmd.replace("{report_file}", report_file)
    
    try:
        proc = run_cmd(cmd.split(), check=False, capture_output=True)
        is_clean = proc.returncode in success_codes
        
        findings = None
        if not is_clean and report_file and os.path.exists(report_file):
            try:
                with open(report_file, 'r') as f:
                    findings = json.load(f)
            except Exception:
                findings = f"Exit code {proc.returncode}\nStdout: {proc.stdout}\nStderr: {proc.stderr}"
        elif not is_clean:
            findings = f"Exit code {proc.returncode}\nStdout: {proc.stdout}\nStderr: {proc.stderr}"
            
        return CheckerResult(name, is_clean, findings)
    finally:
        if report_file and os.path.exists(report_file):
            os.remove(report_file)

def run_tactus_checker(checker: Dict[str, Any]) -> CheckerResult:
    name = checker.get('name', 'tactus-scan')
    procedure = checker.get('procedure')
    if not procedure:
        return CheckerResult(name, False, "No procedure specified for tactus checker")
    
    # Mocking tactus invocation based on common patterns
    cmd = ["tactus", "run", procedure]
    proc = run_cmd(cmd, check=False, capture_output=True)
    is_clean = proc.returncode == 0
    return CheckerResult(name, is_clean, proc.stdout if not is_clean else None)

def execute_checkers(checkers: List[Dict[str, Any]]) -> List[CheckerResult]:
    results = []
    for checker in checkers:
        ctype = checker.get('type', 'command')
        if ctype == 'command':
            results.append(run_command_checker(checker))
        elif ctype == 'tactus':
            results.append(run_tactus_checker(checker))
        else:
            results.append(CheckerResult(checker.get('name', 'unknown'), False, f"Unknown checker type: {ctype}"))
    return results

def get_trailer(commit_sha: str, key: str) -> str:
    return run_cmd(["git", "log", "-1", commit_sha, f"--format=%(trailers:key={key},valueonly)"]).stdout.strip()
