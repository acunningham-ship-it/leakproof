"""Self-test for the scoring harness (QA lane / worker-3).

Proves the harness logic is correct TODAY, without waiting on opus-2's scanner: we feed it a
fake scan() and assert it classifies false-pass / false-positive correctly. Keeps this lane
green from commit one, and pins the harness contract the real gate depends on.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from corpus import ALL  # noqa: E402
from harness import blocking, run  # noqa: E402


def _perfect_scan(text):
    """A fake scanner that is right on every case — leaks get a high finding, decoys get none.
    (Uses the corpus's own labels; only for testing the harness, never shipped.)"""
    from corpus import LEAKS
    leak_texts = {c.text for c in LEAKS}
    if text in leak_texts:
        return [{"type": "test", "span": [0, 1], "severity": "high",
                 "reason": "fixture leak", "redaction": "***"}]
    return []


def test_blocking_filters_by_severity():
    findings = [
        {"severity": "low"}, {"severity": "info"},
        {"severity": "medium"}, {"severity": "high"}, {"severity": "critical"},
    ]
    assert len(blocking(findings)) == 3          # medium/high/critical block; low/info don't
    assert blocking([]) == []
    assert blocking(None) == []


def test_perfect_scanner_passes_clean():
    rep = run(_perfect_scan)
    assert rep.passed
    assert rep.false_pass == []
    assert rep.false_positive == []
    assert len(rep.caught) == len(rep.leaks)


def test_harness_detects_false_pass():
    """A scanner that finds nothing must be flagged: every leak becomes a false-pass."""
    rep = run(lambda _t: [])
    assert not rep.passed
    assert len(rep.false_pass) == len(rep.leaks)
    assert rep.false_positive == []             # finding nothing can't false-positive


def test_harness_detects_false_positive():
    """A scanner that blocks everything must be flagged on the decoys."""
    noisy = lambda _t: [{"severity": "high", "type": "x", "span": [0, 1],
                         "reason": "overzealous", "redaction": "***"}]
    rep = run(noisy)
    assert not rep.passed
    assert len(rep.false_positive) == len(rep.decoys)
    assert rep.false_pass == []                 # blocking everything catches every leak


def test_corpus_is_well_formed():
    assert len(ALL) >= 20
    assert all(c.kind in ("leak", "decoy") for c in ALL)
    assert all(c.text for c in ALL)
    # at least a few leaks are tagged as ones plain regex would miss (the semantic-win story)
    assert sum(1 for c in ALL if c.kind == "leak" and c.regex_misses) >= 3
