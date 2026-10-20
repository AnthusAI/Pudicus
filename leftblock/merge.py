"""Limit staged inspection of a merge commit to content that is new.

``gitleaks protect --staged`` diffs the index against HEAD, so for a merge it
reports everything the merged-in branch brings, although that content already
exists in a parent. This module builds a temporary index in which every changed
file holds only the lines absent from the file's versions in all parents. A
checker run with ``GIT_INDEX_FILE`` pointing at it sees only genuinely new lines
(for example a conflict resolution that introduces a secret).

Any failure raises ``MergeScopeError``; callers fall back to the full scan.
"""

import os
import re
import shutil
import subprocess
import tempfile


class MergeScopeError(Exception):
    pass


def _git(repo_root, *args, env=None, input=None):
    proc = subprocess.run(
        ["git", *args], cwd=repo_root, env=env, input=input,
        capture_output=True, check=False,
    )
    if proc.returncode:
        raise MergeScopeError("git " + args[0] + " failed")
    return proc.stdout


def merge_parents(repo_root):
    """Return the MERGE_HEAD commit ids, or [] when no merge is in progress."""
    proc = subprocess.run(
        ["git", "rev-parse", "--git-path", "MERGE_HEAD"],
        cwd=repo_root, capture_output=True, text=True, check=False,
    )
    if proc.returncode or not proc.stdout.strip():
        return []
    path = proc.stdout.strip()
    if not os.path.isabs(path):
        path = os.path.join(repo_root, path)
    try:
        with open(path) as f:
            heads = [line.strip() for line in f if line.strip()]
    except OSError:
        return []
    if any(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", h) is None for h in heads):
        raise MergeScopeError("Unreadable MERGE_HEAD")
    return heads


def _parse_ls(data):
    """Parse ``ls-files -s -z`` or ``ls-tree -r -z`` output to {path: (mode, sha)}."""
    entries = {}
    for record in data.split(b"\0"):
        if not record:
            continue
        meta, _, path = record.partition(b"\t")
        fields = meta.split()
        if fields[1] in (b"blob", b"commit", b"tree"):  # ls-tree: mode type sha
            mode, sha = fields[0], fields[2]
        else:  # ls-files -s: mode sha stage
            mode, sha = fields[0], fields[1]
        entries[path] = (mode.decode(), sha.decode())
    return entries


def _renames(repo_root, parent, tree):
    """Map new path -> old path for renames/copies from ``parent`` to ``tree``."""
    out = _git(repo_root, "diff-tree", "-r", "-M", "-C", "--name-status", "-z", parent, tree)
    fields = out.split(b"\0")
    mapping, i = {}, 0
    while i < len(fields) and fields[i]:
        status = fields[i]
        if status[:1] in (b"R", b"C"):
            mapping[fields[i + 2]] = fields[i + 1]
            i += 3
        else:
            i += 2
    return mapping


class _Blobs:
    def __init__(self, repo_root):
        self.repo_root = repo_root

    def read(self, sha):
        return _git(self.repo_root, "cat-file", "blob", sha)


def _lines(data):
    return data.split(b"\n")


def _strip(line):
    return line.rstrip(b"\r")


def _new_content(current, baselines):
    """Keep only lines of ``current`` that appear in none of ``baselines``."""
    known = set()
    for old in baselines:
        known.update(_strip(line) for line in _lines(old))
    kept = [line for line in _lines(current) if _strip(line) not in known]
    return b"\n".join(kept) + (b"\n" if kept else b"")


def build_scoped_index(repo_root, parents):
    """Write a temporary index scoped to content new relative to all parents.

    Returns the index path; the caller removes it. HEAD is the first parent.
    """
    index_env = dict(os.environ)
    real_index = index_env.get("GIT_INDEX_FILE")
    if not real_index:
        real_index = _git(repo_root, "rev-parse", "--git-path", "index").decode().strip()
    real_index = os.path.join(repo_root, real_index)
    if not os.path.isfile(real_index):
        raise MergeScopeError("No index")

    staged = _parse_ls(_git(repo_root, "ls-files", "-s", "-z"))
    tree = _git(repo_root, "write-tree").decode().strip()
    heads = ["HEAD"] + parents
    trees = []
    renames = []
    for head in heads:
        trees.append(_parse_ls(_git(repo_root, "ls-tree", "-r", "-z", head)))
        renames.append(_renames(repo_root, head, tree))
    head_tree = trees[0]
    blobs = _Blobs(repo_root)

    fd, scoped = tempfile.mkstemp(prefix="leftblock-merge-index-")
    os.close(fd)
    try:
        shutil.copyfile(real_index, scoped)
        env = dict(os.environ, GIT_INDEX_FILE=scoped)
        updates = []
        for path, (mode, sha) in staged.items():
            if head_tree.get(path) == (mode, sha):
                continue  # unchanged relative to HEAD: not in the diff
            if mode == "160000":
                continue  # submodule pointer: nothing to line-scan
            sources = []
            for parent_tree, renamed in zip(trees, renames):
                for candidate in (path, renamed.get(path)):
                    entry = parent_tree.get(candidate) if candidate is not None else None
                    if entry is not None:
                        sources.append(entry)
            if any(entry[1] == sha for entry in sources):
                new_sha = None  # identical to a parent's file: nothing new
            else:
                current = blobs.read(sha)
                old = [blobs.read(s) for _, s in sources]
                if b"\0" in current:
                    continue  # new or changed binary content: leave as is
                new_content = _new_content(current, old)
                new_sha = (
                    _git(repo_root, "hash-object", "-w", "--stdin", env=env, input=new_content)
                    .decode().strip()
                    if new_content else None
                )
            updates.append((path, mode, new_sha))
        lines = []
        for path, mode, new_sha in updates:
            if new_sha is None:
                # Present in HEAD: restore HEAD's version (no diff). Else drop.
                if path in head_tree:
                    hmode, hsha = head_tree[path]
                    lines.append(b"%s %s 0\t%s\0" % (hmode.encode(), hsha.encode(), path))
                else:
                    lines.append(b"0 %s 0\t%s\0" % (b"0" * len(tree), path))
            else:
                lines.append(b"%s %s 0\t%s\0" % (mode.encode(), new_sha.encode(), path))
        if lines:
            _git(repo_root, "update-index", "-z", "--index-info", env=env, input=b"".join(lines))
        return scoped
    except BaseException:
        if os.path.exists(scoped):
            os.remove(scoped)
        raise
