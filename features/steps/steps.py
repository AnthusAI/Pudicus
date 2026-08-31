import os
import subprocess
import tempfile
import shutil
from behave import given, when, then
from textwrap import dedent

def run_cmd(cmd, cwd=None, **kwargs):
    return subprocess.run(cmd, shell=True, cwd=cwd, text=True, capture_output=True, **kwargs)

@given('a configured pudicus installation with a mock {scanner_type} scanner')
def step_impl(context, scanner_type):
    # Setup a temporary git repository for testing
    context.temp_dir = tempfile.mkdtemp()
    context.repo_dir = os.path.join(context.temp_dir, "repo")
    
    # Init git repo
    os.makedirs(context.repo_dir)
    run_cmd("git init", cwd=context.repo_dir)
    run_cmd('git config user.email "test@example.com"', cwd=context.repo_dir)
    run_cmd('git config user.name "Test User"', cwd=context.repo_dir)
    run_cmd('git commit --allow-empty -m "initial commit"', cwd=context.repo_dir)
    
    # Create pudicus config
    config_path = os.path.join(context.repo_dir, ".pudicus.yml")
    if scanner_type == "successful":
        exit_code = 0
    else:
        exit_code = 1
        
    config_yaml = f"""
version: 1
checkers:
  - name: mock-scanner
    type: command
    command: sh -c 'exit {exit_code}'
    success_codes: [0]
"""
    with open(config_path, 'w') as f:
        f.write(config_yaml)
        
    # Setup pudicus secret
    context.secret_dir = os.path.join(context.temp_dir, ".config", "pudicus")
    os.makedirs(context.secret_dir, exist_ok=True)
    context.secret_path = os.path.join(context.secret_dir, "secret")
    with open(context.secret_path, 'w') as f:
        f.write("mock-secret-12345")
        
    context.env = os.environ.copy()
    context.env["PUDICUS_SECRET_PATH"] = context.secret_path
    context.env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

@given('a staged file containing {content_type}')
def step_impl(context, content_type):
    file_path = os.path.join(context.repo_dir, "testfile.txt")
    with open(file_path, 'w') as f:
        if content_type == "safe content":
            f.write("safe code\n")
        else:
            f.write("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
            
    run_cmd("git add testfile.txt", cwd=context.repo_dir)
    run_cmd("git add .pudicus.yml", cwd=context.repo_dir)
    
    context.msg_file = os.path.join(context.repo_dir, "commit_msg.txt")
    with open(context.msg_file, 'w') as f:
        f.write("test: initial commit\n")

@when('I run the pudicus hook')
def step_impl(context):
    cmd = f"python3 -m pudicus.cli hook {context.msg_file}"
    context.result = subprocess.run(
        cmd, shell=True, cwd=context.repo_dir, text=True, capture_output=True, env=context.env
    )

@when('I run the pudicus hook without a TTY')
def step_impl(context):
    # Running without a pty will automatically act as without a TTY
    cmd = f"python3 -m pudicus.cli hook {context.msg_file}"
    context.result = subprocess.run(
        cmd, shell=True, cwd=context.repo_dir, text=True, capture_output=True, env=context.env
    )

@then('the commit should be allowed')
def step_impl(context):
    assert context.result.returncode == 0, f"Expected success but got {context.result.returncode}\n{context.result.stderr}"

@then('the commit should be blocked')
def step_impl(context):
    assert context.result.returncode != 0, "Expected failure but got 0"

@then('the commit message should contain an "{trailer}" trailer')
def step_impl(context, trailer):
    with open(context.msg_file, 'r') as f:
        content = f.read()
    assert trailer in content, f"Trailer {trailer} not found in {content}"

@then('the commit message should not contain an "{trailer}" trailer')
def step_impl(context, trailer):
    with open(context.msg_file, 'r') as f:
        content = f.read()
    assert trailer not in content, f"Trailer {trailer} unexpectedly found in {content}"

@given('a commit with a valid signature for its tree hash')
def step_impl(context):
    # Same setup as a successful commit
    context.execute_steps('''
        Given a configured pudicus installation with a mock successful scanner
        And a staged file containing safe content
        When I run the pudicus hook
    ''')
    # Actually create the commit with the modified message file
    run_cmd(f"git commit -F {context.msg_file}", cwd=context.repo_dir)
    context.commit_sha = run_cmd("git rev-parse HEAD", cwd=context.repo_dir).stdout.strip()

@given('a commit with no pudicus trailers')
def step_impl(context):
    context.execute_steps('''
        Given a configured pudicus installation with a mock successful scanner
    ''')
    file_path = os.path.join(context.repo_dir, "testfile.txt")
    with open(file_path, 'w') as f:
        f.write("safe code\n")
    run_cmd("git add testfile.txt", cwd=context.repo_dir)
    run_cmd('git commit -m "no trailers"', cwd=context.repo_dir)
    context.commit_sha = run_cmd("git rev-parse HEAD", cwd=context.repo_dir).stdout.strip()

@when('I run the pudicus verify command on the commit')
def step_impl(context):
    cmd = f"python3 -m pudicus.cli verify {context.commit_sha}"
    context.result = subprocess.run(
        cmd, shell=True, cwd=context.repo_dir, text=True, capture_output=True, env=context.env
    )

@then('the verification should pass')
def step_impl(context):
    assert context.result.returncode == 0, f"Verification failed:\n{context.result.stderr}"

@then('the verification should fail')
def step_impl(context):
    assert context.result.returncode != 0, "Verification unexpectedly passed"

def after_scenario(context, scenario):
    if hasattr(context, 'temp_dir') and os.path.exists(context.temp_dir):
        shutil.rmtree(context.temp_dir)

@then('the commit message should contain a valid "{trailer}" trailer')
def step_impl(context, trailer):
    with open(context.msg_file, 'r') as f:
        content = f.read()
    assert trailer in content, f"Trailer {trailer} not found in {content}"

@given('a range of {count:d} unsigned commits')
def step_impl(context, count):
    # Disable the hook temporarily to create unsigned commits easily
    hook_path = os.path.join(context.repo_dir, ".git", "hooks", "commit-msg")
    if os.path.exists(hook_path):
        os.remove(hook_path)
        
    for i in range(count):
        file_path = os.path.join(context.repo_dir, f"testfile_{i}.txt")
        with open(file_path, 'w') as f:
            f.write(f"safe code {i}\n")
        run_cmd(f"git add testfile_{i}.txt", cwd=context.repo_dir)
        run_cmd(f'git commit -m "unsigned commit {i}"', cwd=context.repo_dir)
        
    context.commit_range = f"HEAD~{count}..HEAD"

@given('an unsigned commit containing a secret')
def step_impl(context):
    hook_path = os.path.join(context.repo_dir, ".git", "hooks", "commit-msg")
    if os.path.exists(hook_path):
        os.remove(hook_path)
        
    file_path = os.path.join(context.repo_dir, "testfile.txt")
    with open(file_path, 'w') as f:
        f.write("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
    run_cmd("git add testfile.txt", cwd=context.repo_dir)
    run_cmd('git commit -m "unsigned commit with secret"', cwd=context.repo_dir)
    context.commit_range = "HEAD~1..HEAD"

@when('I run the pudicus approve command for those commits')
def step_impl(context):
    cmd = f"python3 -m pudicus.cli approve {context.commit_range}"
    context.result = subprocess.run(
        cmd, shell=True, cwd=context.repo_dir, text=True, capture_output=True, env=context.env
    )

@when('I run the pudicus approve command for that commit without a TTY')
def step_impl(context):
    cmd = f"python3 -m pudicus.cli approve {context.commit_range}"
    context.result = subprocess.run(
        cmd, shell=True, cwd=context.repo_dir, text=True, capture_output=True, env=context.env
    )

@then('a new approval commit should be created')
def step_impl(context):
    assert context.result.returncode == 0, f"Expected success but got {context.result.returncode}\n{context.result.stderr}"
    msg = run_cmd("git log -1 --format=%B", cwd=context.repo_dir).stdout
    assert "Retroactive approval" in msg or "retroactive" in msg.lower(), "Approval commit not found"

@then('the approval commit should not be created')
def step_impl(context):
    assert context.result.returncode != 0, "Expected failure but got 0"

@then('the verification should pass for the entire range')
def step_impl(context):
    cmd = f"python3 -m pudicus.cli verify HEAD~3..HEAD" # covers the 2 commits + 1 approval commit
    res = subprocess.run(
        cmd, shell=True, cwd=context.repo_dir, text=True, capture_output=True, env=context.env
    )
    assert res.returncode == 0, f"Verification failed:\n{res.stderr}"

