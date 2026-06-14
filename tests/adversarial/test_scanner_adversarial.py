"""Adversarial gate against the REAL scanner (QA lane / worker-3).

Skips cleanly until opus-2's scanner lane lands (keeps master green), then becomes the hard
DLP gate: zero false-pass (no real secret slips through) and zero false-positive (no decoy
blocked). If this test fails, the scanner is not safe to ship — that's the point.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

scanner = pytest.importorskip(
    "leakproof.scanner",
    reason="scanner lane not merged yet — corpus + harness are ready and will gate it",
)

from corpus import DECOYS, LEAKS  # noqa: E402
from harness import blocking, run  # noqa: E402


def _scan():
    return getattr(scanner, "scan")


@pytest.mark.parametrize("case", LEAKS, ids=lambda c: c.id)
def test_no_false_pass(case):
    """Every leak MUST yield at least one blocking finding. A miss here = a shipped secret."""
    findings = _scan()(case.text)
    assert blocking(findings), (
        f"FALSE-PASS: leak '{case.id}' produced no blocking finding — {case.note}"
    )


@pytest.mark.parametrize("case", DECOYS, ids=lambda c: c.id)
def test_no_false_positive(case):
    """No decoy may produce a blocking finding (low/info is tolerated, blocking is not)."""
    findings = _scan()(case.text)
    assert not blocking(findings), (
        f"FALSE-POSITIVE: decoy '{case.id}' was blocked — {case.note}"
    )


def test_scorecard_passes():
    rep = run(_scan())
    assert rep.passed, "\n" + "\n".join(
        [f"false-pass: {r.case.id}" for r in rep.false_pass]
        + [f"false-pos:  {r.case.id}" for r in rep.false_positive]
    )
