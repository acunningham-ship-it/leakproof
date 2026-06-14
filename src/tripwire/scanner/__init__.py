"""tripwire.scanner — the local secret/PII/leak scan-core.

THE locked contract every surface (egress proxy, git hook, QA corpus) builds against:

    scan(text: str, context: dict | None = None) -> list[Finding]
    redact(text: str, findings: list[Finding]) -> str

    Finding = {
        "type": str,            # e.g. "aws_access_key_id", "github_token", "pii_email"
        "span": [start, end],   # char offsets into `text`
        "severity": "critical" | "high" | "medium" | "low",
        "reason": str,          # human-readable why
        "redaction": str,       # replacement token for redact()
        "source": "rules" | "semantic",
    }

`scan()` always runs the zero-dependency regex/entropy fast-path (`rules`), then adds a
best-effort LOCAL-model semantic pass (`semantic`) that catches the shapeless leaks
regex misses. Overlapping findings are de-duplicated, highest severity winning.
`redact()` is pure and offset-safe.
"""

from __future__ import annotations

from typing import Callable

from .rules import SEVERITY_RANK, scan_rules, shannon_entropy
from .semantic import scan_semantic, semantic_enabled

__all__ = [
    "scan",
    "redact",
    "merge_findings",
    "scan_rules",
    "scan_semantic",
    "semantic_enabled",
    "shannon_entropy",
    "SEVERITY_RANK",
]

Finding = dict  # structural; documented above.


def _overlaps(a: list[int], b: list[int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """De-overlap: on overlapping spans keep the higher-severity (then longer) finding.

    Non-overlapping findings all survive. Result is sorted by span start so redaction
    and display are stable.
    """
    ordered = sorted(
        findings,
        key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0),
                       -(f["span"][1] - f["span"][0])),
    )
    kept: list[Finding] = []
    for f in ordered:
        if any(_overlaps(f["span"], k["span"]) for k in kept):
            continue
        kept.append(f)
    kept.sort(key=lambda f: f["span"][0])
    return kept


def scan(
    text: str,
    context: dict | None = None,
    *,
    call_model: Callable[[str], str] | None = None,
) -> list[Finding]:
    """Scan `text` for secrets/PII/leaks. Rules always; semantic best-effort.

    `context` is reserved for callers to pass hints (e.g. {"path": "...", "tool": "..."})
    and is accepted now so the signature never changes under a surface. `call_model` is
    an injection seam for tests / alternate local model transports.
    """
    if not text:
        return []
    findings = scan_rules(text)
    findings += scan_semantic(text, call_model=call_model)
    return merge_findings(findings)


def redact(text: str, findings: list[Finding]) -> str:
    """Replace each finding's span with its redaction token. Offset-safe.

    Applies right-to-left so earlier spans keep their offsets. Overlapping spans are
    merged first (defensive — `scan()` already merges) so we never double-replace.
    """
    if not findings:
        return text
    safe = merge_findings(findings)
    safe.sort(key=lambda f: f["span"][0], reverse=True)
    out = text
    for f in safe:
        start, end = f["span"]
        if start == end:
            continue  # zero-width (document-level) marker — nothing to replace
        if 0 <= start <= end <= len(out):
            out = out[:start] + f["redaction"] + out[end:]
    return out
