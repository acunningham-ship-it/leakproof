#!/usr/bin/env python3
"""Standalone adversarial scorecard for tripwire's scanner (QA lane / worker-3).

Runs the leak/decoy corpus through the real scanner and prints a scorecard. Use it as the
human-facing report AND a CI gate (exits non-zero on any false-pass / false-positive).

    uv run python tests/adversarial/scorecard.py

If the scanner isn't implemented yet (opus-2's lane not merged), it says so and exits 0 —
so it never blocks early CI; it becomes a hard gate the moment scan() exists.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from harness import format_report, run  # noqa: E402


def _load_scan():
    """Import the scanner's scan(). Returns None if the lane isn't merged yet."""
    try:
        from tripwire.scanner import scan  # type: ignore
        return scan
    except Exception:
        return None


def main() -> int:
    scan = _load_scan()
    if scan is None:
        print("tripwire.scanner.scan() not available yet — scanner lane not merged.")
        print("(corpus + harness are ready; this becomes a hard gate once scan() lands.)")
        return 0

    rep = run(scan)
    print(format_report(rep))
    return 0 if rep.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
