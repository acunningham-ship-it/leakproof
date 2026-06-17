"""Scoring harness for the adversarial corpus (QA lane / worker-3).

Pure logic: `run(scan_fn)` takes the scanner's `scan` callable and returns a Report. It does NOT
import the scanner itself, so it's fully decoupled — testable with a fake scan_fn, and reusable
by both the pytest gate and the standalone scorecard.

A finding "blocks" if its severity is medium or above. Decoys must produce ZERO blocking
findings (false-positive); leaks must produce AT LEAST ONE (else false-pass — the cardinal sin).
A low/info finding on a decoy (e.g. a Stripe *test* key) is tolerated — it informs without
blocking the commit.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from corpus import ALL, Case

BLOCKING_SEVERITIES = {"medium", "high", "critical"}


def blocking(findings) -> list:
    """Findings severe enough to block a commit / redact an outbound request."""
    out = []
    for f in findings or []:
        sev = str((f or {}).get("severity", "")).lower()
        if sev in BLOCKING_SEVERITIES:
            out.append(f)
    return out


@dataclass
class CaseResult:
    case: Case
    findings: list
    ok: bool          # leak: caught? / decoy: stayed clean?
    detail: str = ""


@dataclass
class Report:
    results: list[CaseResult] = field(default_factory=list)
    false_pass: list[CaseResult] = field(default_factory=list)   # leaks NOT caught — must be empty
    false_positive: list[CaseResult] = field(default_factory=list)  # decoys that blocked — must be empty

    @property
    def leaks(self):
        return [r for r in self.results if r.case.kind == "leak"]

    @property
    def decoys(self):
        return [r for r in self.results if r.case.kind == "decoy"]

    @property
    def caught(self):
        return [r for r in self.leaks if r.ok]

    @property
    def passed(self) -> bool:
        """The gate: every leak caught AND no decoy blocked."""
        return not self.false_pass and not self.false_positive


def run(scan_fn, cases: list[Case] | None = None) -> Report:
    """Run every case through scan_fn and score it. scan_fn(text) -> list[finding-dict]."""
    rep = Report()
    for case in cases or ALL:
        findings = scan_fn(case.text)
        blockers = blocking(findings)
        if case.kind == "leak":
            ok = len(blockers) >= 1
            res = CaseResult(case, findings, ok,
                             "caught" if ok else "MISSED (false-pass)")
            if not ok:
                rep.false_pass.append(res)
        else:  # decoy
            ok = len(blockers) == 0
            res = CaseResult(case, findings, ok,
                             "clean" if ok else f"FALSE-POSITIVE ({len(blockers)} blocking)")
            if not ok:
                rep.false_positive.append(res)
        rep.results.append(res)
    return rep


def format_report(rep: Report) -> str:
    leaks, decoys = rep.leaks, rep.decoys
    lines = []
    lines.append("=" * 64)
    lines.append("  leakproof scanner — adversarial scorecard")
    lines.append("=" * 64)
    lines.append(f"  leaks caught     : {len(rep.caught)}/{len(leaks)}")
    lines.append(f"  false-pass       : {len(rep.false_pass)}   (MUST be 0 — a real secret slipped through)")
    lines.append(f"  decoys clean     : {len(decoys) - len(rep.false_positive)}/{len(decoys)}")
    lines.append(f"  false-positive   : {len(rep.false_positive)}   (clean code wrongly blocked)")
    regex_hard = [r for r in rep.caught if r.case.regex_misses]
    lines.append(f"  regex-hard caught: {len(regex_hard)} leak(s) a keyword-only scanner would miss (entropy/structure, no model)")
    lines.append("-" * 64)
    for r in rep.false_pass:
        lines.append(f"  ✗ FALSE-PASS  [{r.case.id}] {r.case.note}")
    for r in rep.false_positive:
        lines.append(f"  ✗ FALSE-POS   [{r.case.id}] {r.case.note}")
    if rep.passed:
        lines.append("  ✓ PASS — every leak caught, no decoy blocked")
    else:
        lines.append("  ✗ FAIL — see findings above")
    lines.append("=" * 64)
    return "\n".join(lines)
