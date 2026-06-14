"""Tests for leakproof.audit + leakproof.audit_demo (L3 audit lane).

Runs under pytest OR standalone: `python tests/test_audit.py`.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

# allow standalone run without install
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from leakproof import audit, audit_demo  # noqa: E402
from leakproof.audit import AuditEvent, Finding, aggregate, categorize  # noqa: E402


def test_categorize():
    assert categorize("aws_secret_key") == "secret"
    assert categorize("openai_key") == "secret"
    assert categorize("pii_email") == "pii"
    assert categorize("email") == "pii"
    assert categorize("source_file") == "file"
    assert categorize("full_file") == "file"
    assert categorize("weird_new_file") == "file"   # *_file fallback
    assert categorize("something_pii_ish") == "pii"  # substring fallback
    assert categorize("unknown") == "other"


def test_event_roundtrip():
    ev = AuditEvent(
        source="proxy", tool="claude-code", host="api.anthropic.com",
        action="blocked", bytes_in=100, bytes_redacted=100,
        findings=[Finding("aws_secret_key", [1, 5], "critical", "why", "‹x›")],
    )
    line = ev.to_json()
    back = AuditEvent.from_json(line)
    assert back.source == "proxy"
    assert back.tool == "claude-code"
    assert back.action == "blocked"
    assert back.n_findings == 1
    assert back.findings[0].type == "aws_secret_key"
    assert back.findings[0].span == [1, 5]
    # n_findings is written for plain-json consumers (e.g. the TUI in JS)
    assert json.loads(line)["n_findings"] == 1


def test_from_dict_tolerates_minimal_and_plain_findings():
    ev = AuditEvent.from_dict({
        "source": "hook", "action": "blocked",
        "findings": [{"type": "stripe_key", "severity": "critical"}],
    })
    assert ev.source == "hook"
    assert ev.findings[0].type == "stripe_key"
    assert ev.findings[0].span == [0, 0]   # defaulted
    assert ev.id and len(ev.id) >= 8       # auto id


def test_record_and_read(tmp_path: Path | None = None):
    p = Path(tmp_path) / "a.jsonl" if tmp_path else Path(tempfile.mkdtemp()) / "a.jsonl"
    audit.record(AuditEvent(source="proxy", tool="aider", action="passed", bytes_in=10), path=p)
    audit.record({"source": "hook", "action": "blocked",
                  "findings": [{"type": "jwt", "severity": "high"}]}, path=p)
    events = audit.read_events(p)
    assert len(events) == 2
    assert events[0].tool == "aider"
    assert events[1].source == "hook"
    assert events[1].n_findings == 1


def test_read_skips_malformed_lines(tmp_path: Path | None = None):
    p = Path(tmp_path) / "b.jsonl" if tmp_path else Path(tempfile.mkdtemp()) / "b.jsonl"
    good = AuditEvent(source="proxy", action="passed").to_json()
    p.write_text(good + "\n" + "{not json at all\n" + "\n" + good + "\n")
    events = audit.read_events(p)
    assert len(events) == 2   # two good, garbage + blank skipped


def test_read_missing_file_is_empty():
    assert audit.read_events("/nonexistent/airlock/audit.jsonl") == []


def test_aggregate_totals(tmp_path: Path | None = None):
    events = [
        AuditEvent(source="proxy", tool="claude-code", action="blocked",
                   bytes_in=1000, bytes_redacted=1000,
                   findings=[Finding("aws_secret_key"), Finding("env_value")]),
        AuditEvent(source="proxy", tool="cursor", action="redacted",
                   bytes_in=500, bytes_redacted=50,
                   findings=[Finding("openai_key"), Finding("pii_email")]),
        AuditEvent(source="hook", tool="git", action="blocked",
                   bytes_in=200, bytes_redacted=200,
                   findings=[Finding("source_file")]),
        AuditEvent(source="proxy", tool="aider", action="passed",
                   bytes_in=300, findings=[]),
    ]
    t = aggregate(events)
    assert t.requests == 4
    assert t.secrets == 3        # aws, env_value, openai
    assert t.pii == 1            # pii_email
    assert t.files == 1          # source_file
    assert t.blocked == 2
    assert t.redacted == 1
    assert t.passed == 1
    assert t.bytes_in == 2000
    # blocked count full bytes_in (1000+200), redacted counts bytes_redacted (50)
    assert t.bytes_protected == 1250
    assert t.caught == 5         # 3 secrets + 1 pii + 1 file
    assert t.by_tool["claude-code"] == 1
    assert t.by_source["proxy"] == 3
    assert t.by_source["hook"] == 1


def test_aggregate_accepts_dicts():
    t = aggregate([{"source": "proxy", "action": "blocked", "bytes_in": 10,
                    "bytes_redacted": 10,
                    "findings": [{"type": "github_token"}]}])
    assert t.secrets == 1
    assert t.bytes_protected == 10


def test_demo_generate(tmp_path: Path | None = None):
    p = Path(tmp_path) / "demo.jsonl" if tmp_path else Path(tempfile.mkdtemp()) / "demo.jsonl"
    out = audit_demo.generate(p)
    assert out == p
    events = audit.read_events(p)
    assert len(events) >= 8
    t = aggregate(events)
    # the demo must actually demonstrate catches (the whole point)
    assert t.caught > 0
    assert t.blocked > 0
    assert t.redacted > 0
    assert len(t.by_tool) >= 3            # claude-code, cursor, aider
    # timestamps strictly increasing (clean live-tail render)
    ts = [e.ts for e in events]
    assert ts == sorted(ts)


def test_demo_contains_no_real_looking_live_secret():
    """Committed demo data must be obviously fake."""
    p = Path(tempfile.mkdtemp()) / "demo.jsonl"
    audit_demo.generate(p)
    raw = p.read_text()
    # every secret value is redacted/marked — no raw key material in the file
    assert "BEGIN PRIVATE KEY----- ‹redacted›" in raw
    assert "‹redacted›" in raw
    # no bare AKIA... access key id leaked into the fixture
    assert "AKIA" not in raw


def test_follow_reads_appended(tmp_path: Path | None = None):
    """follow() yields events appended after it starts (bounded check)."""
    import threading
    import time
    p = Path(tmp_path) / "f.jsonl" if tmp_path else Path(tempfile.mkdtemp()) / "f.jsonl"
    p.write_text("")
    got = []

    def consume():
        for ev in audit.follow(p, poll=0.02, from_start=True):
            got.append(ev)
            if len(got) >= 3:
                return

    th = threading.Thread(target=consume, daemon=True)
    th.start()
    for i in range(3):
        audit.record(AuditEvent(source="proxy", action="passed", bytes_in=i), path=p)
        time.sleep(0.03)
    th.join(timeout=3)
    assert len(got) == 3


# --- standalone runner ------------------------------------------------------

def _run_all():
    import inspect
    tmp = Path(tempfile.mkdtemp())
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        params = inspect.signature(fn).parameters
        try:
            fn(tmp) if "tmp_path" in params else fn()
            print(f"  ok  {fn.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            print(f" FAIL {fn.__name__}: {e!r}")
            raise
    print(f"\n{passed}/{len(fns)} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
