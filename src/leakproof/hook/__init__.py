"""leakproof.hook lane — block secrets/PII before they hit git (leakproof Surface B).

CLI entry points (worker-claude's contract #386, return process exit codes):
  install(repo=".") -> int          # `leakproof install-hook`
  uninstall(repo=".") -> int        # `leakproof uninstall-hook`
  run(repo=".") -> int              # the installed git hook runs `python -m leakproof.hook`

Rich/underlying API:
  install_hook(repo, command, force) -> hook_path
  uninstall_hook(repo) -> bool
  check(*, get_diff, scan, redact, record, threshold, mode, repo, out) -> int
  real_staged_diff(repo) -> str
  parse_added_lines(diff_text) -> [(file, lineno, text)]
"""
from .core import check, parse_added_lines, real_staged_diff, run
from .install import install, install_hook, uninstall, uninstall_hook

__all__ = [
    "install",
    "uninstall",
    "run",
    "check",
    "install_hook",
    "uninstall_hook",
    "real_staged_diff",
    "parse_added_lines",
]
