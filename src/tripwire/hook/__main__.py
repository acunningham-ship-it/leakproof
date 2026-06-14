"""`python -m tripwire.hook` — what the installed git pre-commit hook execs.

Self-contained so the hook works whether or not the `leakproof` console script
is on PATH. Scans the staged diff; exit 1 blocks the commit.
"""
import sys

from .core import run

if __name__ == "__main__":
    sys.exit(run())
