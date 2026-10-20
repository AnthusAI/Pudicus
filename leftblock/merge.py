"""Conservatively scope command checkers during an in-progress merge.

Only regular files whose complete blob AND mode already exist at the same path
in a merge parent are omitted from the staged diff. This avoids reporting an
unchanged imported file as newly introduced material. It does not establish that
the inherited content is safe.

Modified/resolved files, renamed paths absent from every parent, binary changes
and submodule pointers retain their normal staged representation. In particular,
we never remove individual known lines: their new context or combination can
create a sensitive value. Any scoping error falls back to the full staged scan.
"""

import os
import re
import shutil
import subprocess
import tempfile
from leftblock.core import index_environment


class MergeScopeError(Exception):
    """A safe temporary index could not be constructed."""


def _git(repo_root, *args, env=None, input=None):
    proc = subprocess.run(
        ["git", *args], cwd=repo_root, env=index_environment(env), input=input,
        capture_output=True, check=False,
    )
    if proc.returncode:
        # Do not include repository contents or raw Git diagnostics.
        raise MergeScopeError("git " + args[0] + " failed")
    return proc.stdout


def merge_parents(repo_root):
    """Return MERGE_HEAD commit IDs, or [] outside an in-progress merge."""
    path = _git(repo_root, "rev-parse", "--git-path", "MERGE_HEAD").decode().strip()
    if not path:
        raise MergeScopeError("Missing merge state path")
    if not os.path.isabs(path):
        path = os.path.join(repo_root, path)
    try:
        with open(path) as stream:
            heads = [line.strip() for line in stream if line.strip()]
    except FileNotFoundError:
        return []
    if not heads or any(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head) is None for head in heads):
        raise MergeScopeError("Invalid merge state")
    return heads


def merge_state(repo_root):
    """Pin the current parent commits; callers recheck after scoped inspection."""
    parents = merge_parents(repo_root)
    if not parents:
        return None
    head = _git(repo_root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head) is None:
        raise MergeScopeError("Invalid HEAD")
    for parent in parents:
        resolved = _git(repo_root, "rev-parse", "--verify", parent + "^{commit}").decode().strip()
        if resolved != parent:
            raise MergeScopeError("Invalid merge parent")
    return head, tuple(parents)


def checker_environment(scoped_index=None):
    """Expose rename content, optionally using the private merge index."""
    env = dict(os.environ)
    if scoped_index:
        env["GIT_INDEX_FILE"] = scoped_index
    env = index_environment(env)
    count = int(env.get("GIT_CONFIG_COUNT", "0"))
    if count < 0:
        raise MergeScopeError("Invalid Git environment")
    env["GIT_CONFIG_KEY_" + str(count)] = "diff.renames"
    env["GIT_CONFIG_VALUE_" + str(count)] = "false"
    env["GIT_CONFIG_COUNT"] = str(count + 1)
    return env


def _parse_ls(data, staged=False):
    """Parse NUL-separated Git index/tree records without interpreting paths."""
    entries = {}
    for record in data.split(b"\0"):
        if not record:
            continue
        meta, separator, path = record.partition(b"\t")
        fields = meta.split()
        if not separator or not path or len(fields) != 3 or path in entries:
            raise MergeScopeError("Invalid Git entry")
        if staged:
            mode, sha, stage = fields
            if stage != b"0":
                raise MergeScopeError("Unresolved index")
        else:
            mode, kind, sha = fields
            if kind not in (b"blob", b"commit"):
                raise MergeScopeError("Unsupported Git entry")
        if re.fullmatch(rb"[0-7]{6}", mode) is None or re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", sha) is None:
            raise MergeScopeError("Invalid Git entry")
        entries[path] = (mode, sha)
    return entries


def index_entries(repo_root, scoped_index):
    """Canonical staged entries, also used to reject checker index mutations."""
    return _parse_ls(
        _git(repo_root, "ls-files", "-s", "-z", env=dict(os.environ, GIT_INDEX_FILE=scoped_index)),
        staged=True,
    )


def build_scoped_index(repo_root, parents, head="HEAD"):
    """Return an owned temporary index; the caller removes it after checking.

    Read the staged snapshot through the copy, not the live index. No blobs,
    trees, refs or original index bytes are written by this operation. A caller
    must still compare the real staged tree before and after checking.
    """
    if not parents or any(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head) is None for head in parents):
        raise MergeScopeError("Invalid merge parents")
    alternate_index = os.environ.get("GIT_INDEX_FILE")
    if alternate_index:
        real_index = os.path.abspath(alternate_index)
    else:
        real_index = _git(repo_root, "rev-parse", "--git-path", "index").decode().strip()
        if not real_index:
            raise MergeScopeError("Missing index path")
        real_index = os.path.abspath(os.path.join(repo_root, real_index))
    if not os.path.isfile(real_index):
        raise MergeScopeError("No index")

    fd, scoped = tempfile.mkstemp(prefix="leftblock-merge-index-")
    os.close(fd)
    try:
        shutil.copyfile(real_index, scoped)
        env = dict(os.environ, GIT_INDEX_FILE=scoped)
        # Expand sparse-directory entries and resolve split-index references
        # through Git before modifying the private copy.
        staged = index_entries(repo_root, scoped)
        trees = [
            _parse_ls(_git(repo_root, "ls-tree", "-r", "-z", head))
            for head in [head] + list(parents)
        ]
        head_tree = trees[0]
        updates = []
        for path, (mode, sha) in staged.items():
            if head_tree.get(path) == (mode, sha):
                continue
            if mode not in (b"100644", b"100755"):
                continue
            if not any(parent.get(path) == (mode, sha) for parent in trees[1:]):
                continue
            if path in head_tree:
                old_mode, old_sha = head_tree[path]
                updates.append(b"%s %s 0\t%s\0" % (old_mode, old_sha, path))
            else:
                updates.append(b"0 %s 0\t%s\0" % (b"0" * len(sha), path))
        if updates:
            _git(
                repo_root, "-c", "core.splitIndex=false", "-c", "index.sparse=false",
                "update-index", "--no-split-index", "-z", "--index-info",
                env=env, input=b"".join(updates),
            )
        return scoped
    except BaseException:
        if os.path.exists(scoped):
            os.remove(scoped)
        raise
