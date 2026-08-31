# Pudicus

Pudicus ("modest, chaste, keeping pure") is a standalone, pluggable inspection gate for Git commits. It ensures that required scans (like secret detection or agent-based reviews) are executed against staged changes, producing cryptographically verifiable signatures required for deployment.

## Installation

Install using `pipx` or `pip` (global or virtualenv):

```bash
pip install -e .
pudicus install
```

## Configuration

Add a `.pudicus.yml` file to the root of your repository:

```yaml
version: 1

checkers:
  # Standard CLI scanner
  - name: gitleaks
    type: command
    command: gitleaks protect --staged --report-format json --report-path {report_file}
    success_codes: [0]
    finding_codes: [1]

  # Agent-based custom scan
  - name: tactus-security-review
    type: tactus
    procedure: security_review
```

## Usage

Once installed, Pudicus runs automatically as a `commit-msg` git hook.

If all checks pass, your commit is cryptographically signed using a shared HMAC secret.

If checks fail, you will be prompted for an override passphrase. If you are an agent running in a headless environment, the commit will be blocked.

## Verification (Deploy Gate)

In your CI/CD pipeline, run:

```bash
pudicus verify HEAD~5..HEAD
```

This ensures that all commits in the deployment range have been successfully signed and the tree hasn't been tampered with.
