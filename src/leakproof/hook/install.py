"""leakproof pre-commit hook installer.

install() drops a pre-commit hook into the repo's git hooks dir that scans the
staged diff via `python -m leakproof.hook`. Self-contained (no dependence on the
`leakproof` console script being on PATH). Backs up any existing hook so we never
silently clobber the user's setup; uninstall() restores it. Worktree-safe
(resolves the real hooks path via `git rev-parse --git-path hooks`).
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys

MARKER = "# leakproof pre-commit hook"
HOOK_TEMPLATE = """#!/bin/sh
{marker} (DLP: blocks secrets/PII before they hit git)
exec {command}
"""
# Captured at install time, in the user's environment → robust across the
# leakproof→leakproof rename and across machines. `leakproof precommit` is a nicer
# published alias once cli wires it (worker-claude), but this always works.
DEFAULT_COMMAND = f"{sys.executable} -m leakproof.hook"
BACKUP_SUFFIX = ".leakproof-backup"


def _hooks_dir(repo: str) -> str:
    out = subprocess.run(
        ["git", "rev-parse", "--git-path", "hooks"],
        cwd=repo, capture_output=True, text=True, check=True,
    )
    path = out.stdout.strip()
    return path if os.path.isabs(path) else os.path.join(repo, path)


def install(repo: str = ".") -> int:
    """CLI entry point (`leakproof install-hook`). Returns a process exit code.
    Never raises — a conflict prints guidance and returns 1 instead of crashing."""
    try:
        path = install_hook(repo)
        print(f"  leakproof: pre-commit hook installed → {path}")
        return 0
    except FileExistsError as e:
        print(f"  leakproof: {e}")
        return 1


def uninstall(repo: str = ".") -> int:
    """CLI entry point (`leakproof uninstall-hook`). Returns a process exit code."""
    changed = uninstall_hook(repo)
    print("  leakproof: hook removed." if changed else "  leakproof: no leakproof hook to remove.")
    return 0


def install_hook(repo: str = ".", command: str = DEFAULT_COMMAND, force: bool = False) -> str:
    """Install the pre-commit hook. Returns the hook path. Raises if one exists
    and force is False (after backing nothing up)."""
    hooks = _hooks_dir(repo)
    os.makedirs(hooks, exist_ok=True)
    hook_path = os.path.join(hooks, "pre-commit")

    if os.path.exists(hook_path):
        existing = _read(hook_path)
        if MARKER in existing:
            # already ours — idempotent refresh
            pass
        elif force:
            shutil.copy2(hook_path, hook_path + BACKUP_SUFFIX)
        else:
            raise FileExistsError(
                f"{hook_path} already exists. Re-run with force=True to back it up "
                f"(saved to *{BACKUP_SUFFIX}) and replace it."
            )

    _write(hook_path, HOOK_TEMPLATE.format(marker=MARKER, command=command))
    _make_executable(hook_path)
    return hook_path


def uninstall_hook(repo: str = ".") -> bool:
    """Remove our hook and restore any backup. Returns True if something changed.
    Refuses to delete a hook that isn't ours."""
    hooks = _hooks_dir(repo)
    hook_path = os.path.join(hooks, "pre-commit")
    backup = hook_path + BACKUP_SUFFIX

    if not os.path.exists(hook_path):
        if os.path.exists(backup):
            shutil.move(backup, hook_path)
            return True
        return False

    if MARKER not in _read(hook_path):
        # not ours — leave it alone
        return False

    os.remove(hook_path)
    if os.path.exists(backup):
        shutil.move(backup, hook_path)
    return True


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def _make_executable(path: str) -> None:
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
