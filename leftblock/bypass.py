"""Findings for the two ways Gitleaks can be told to skip content silently.

Gitleaks honours an inline allow comment and `.gitleaksignore`
files without any recorded reason. LeftBlock reports staged additions of
either as findings of its own, so they are blocked by default and can be
overridden only through a recorded, reviewed override like any other finding.
"""

import re
import subprocess

# Split so this repository does not trip its own check.
MARKER = "gitleaks" + ":allow"
IGNORE_FILE = ".gitleaksignore"
MARKER_RULE = "leftblock-gitleaks-allow-marker"
IGNORE_RULE = "leftblock-gitleaksignore-change"
# Descriptions are written into the allow file as `kind`, so they must not
# contain the marker themselves.
RULE_DESCRIPTIONS = {
    MARKER_RULE: "Inline Gitleaks allow comment (skips the scanner with no recorded reason)",
    IGNORE_RULE: "Change to .gitleaksignore (skips the scanner with no recorded reason)",
}

_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_ESCAPES = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, '"': 34, "\\": 92}


class BypassScanError(Exception):
    pass


def _git(repo_root, env, *args):
    proc = subprocess.run(
        ["git", *args], cwd=repo_root, env=env, capture_output=True, check=False,
        stdin=subprocess.DEVNULL,
    )
    if proc.returncode:
        raise BypassScanError("git " + args[0] + " failed")
    return proc.stdout


def _unquote(path):
    """Decode a path as Git prints it (C-style quoting when it has odd bytes)."""
    if not (path.startswith(b'"') and path.endswith(b'"') and len(path) >= 2):
        return path
    out, i, body = bytearray(), 0, path[1:-1]
    while i < len(body):
        c = body[i]
        if c != 0x5C:
            out.append(c)
            i += 1
        elif body[i + 1:i + 2].isdigit() and re.fullmatch(rb"[0-7]{3}", body[i + 1:i + 4]):
            out.append(int(body[i + 1:i + 4], 8))
            i += 4
        else:
            out.append(_ESCAPES.get(chr(body[i + 1]), body[i + 1]))
            i += 2
    return bytes(out)


def _added_lines(diff):
    """Yield (path, line_number, text) for each added line in a -U0 patch.

    Hunk line counts decide which lines are content, so an added line that
    itself starts with "++" or "@@" cannot be mistaken for a header.
    """
    path, line, old_left, new_left = None, 0, 0, 0
    for raw in diff.split(b"\n"):
        if old_left or new_left:
            if raw.startswith(b"-"):
                old_left -= 1
            elif raw.startswith(b"+"):
                new_left -= 1
                if path is not None:
                    yield path, line, raw[1:]
                line += 1
            continue
        if raw.startswith(b"+++ "):
            target = _unquote(raw[4:])
            path = None if target == b"/dev/null" else target[2:].decode("utf-8", "replace")
        elif raw.startswith(b"@@"):
            hunk = _HUNK.match(raw.decode("utf-8", "replace"))
            if hunk:
                old_left = int(hunk.group(1) or 1)
                line = int(hunk.group(2))
                new_left = int(hunk.group(3) or 1)


def bypass_findings(repo_root, env=None):
    """Findings (File, RuleID, StartLine, EndLine, description) for staged bypasses.

    Reads the staged diff through `env`, which carries the merge-scoped index
    when one is in use. Raises BypassScanError when the diff cannot be read.
    """
    diff = _git(
        repo_root, env, "-c", "core.quotePath=false", "diff", "--cached", "-U0",
        "--no-color", "--no-ext-diff", "--no-renames", "--text",
    )
    findings = []
    for path, number, text in _added_lines(diff):
        if MARKER.encode() in text:
            findings.append({
                "File": path, "RuleID": MARKER_RULE, "StartLine": number, "EndLine": number,
                "description": RULE_DESCRIPTIONS[MARKER_RULE],
            })
    names = _git(
        repo_root, env, "diff", "--cached", "--name-only", "-z", "--no-renames",
        "--diff-filter=AMT",
    )
    for raw in names.split(b"\0"):
        path = raw.decode("utf-8", "replace")
        if path and (path == IGNORE_FILE or path.endswith("/" + IGNORE_FILE)):
            blob = _git(repo_root, env, "show", ":" + path)
            lines = len(blob.decode("utf-8", "replace").split("\n"))
            findings.append({
                "File": path, "RuleID": IGNORE_RULE, "StartLine": 1, "EndLine": lines,
                "description": RULE_DESCRIPTIONS[IGNORE_RULE],
            })
    return findings
