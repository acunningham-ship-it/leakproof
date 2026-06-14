"""airlock audit log — the seam between the surfaces (proxy/hook) and the TUI.

Both surfaces append one JSON object per inspected payload to an append-only
JSONL file. The TUI tails that file and renders it; `aggregate()` rolls a list
of events into the "shock totals" the dashboard headlines with.

The *contract* between lanes is the JSON line shape (`AuditEvent`) — any lane
can emit a conformant line with `json.dumps` and no import. `record()` is the
convenience writer the proxy (L1) and hook surfaces call.

Locked event shape (worker-opus-4 #371 + worker-2 Finding #370 + opus-5 #369):
  {id, ts, source, tool, method, host, url, target, action,
   findings:[{type, span:[s,e], severity, reason, redaction, source}],
   n_findings, bytes_in, bytes_redacted, preview}

Audit log path (first match wins):
  1. $AIRLOCK_AUDIT_LOG
  2. $LEAKPROOF_AUDIT_LOG   (compat during the leakproof->airlock rename)
  3. ~/.local/share/airlock/audit.jsonl
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator

# --- finding categories (for rollups) --------------------------------------

# Scanner (L2) finding types, grouped so the TUI can total them. Matching is
# lenient: exact membership first, then a substring fallback, so a new or
# variant scanner type still lands in a sane bucket instead of vanishing.
#
# The exact sets include worker-2's real scanner vocabulary (rules.py _PATTERNS:
# aws_access_key_id, stripe_secret_key, db_url_with_credentials, high_entropy_string,
# generic_secret_assignment, github_pat, google_api_key, secret, bulk_source_paste,
# pii_email/pii_phone/credit_card) — verified live, NOT the audit_demo's idealized
# names. Mismatch here silently zeroed the "N secrets stopped" headline (opus-4
# integration smoke #404 follow-up), so the substring fallback below is the real
# guard: it survives renames + new detectors without desyncing the hero metric.
SECRET_TYPES = {
    "aws_access_key", "aws_access_key_id", "aws_secret_key", "github_token",
    "github_pat", "gitlab_token", "openai_key", "anthropic_key", "google_api_key",
    "stripe_key", "stripe_secret_key", "slack_token", "jwt", "private_key",
    "generic_secret", "generic_secret_assignment", "secret", "env_value",
    "db_url", "db_url_with_credentials", "high_entropy", "high_entropy_string",
}
PII_TYPES = {"email", "pii_email", "phone", "pii_phone", "credit_card", "ssn", "pii"}
FILE_TYPES = {"full_file", "source_file", "bulk_source_paste"}

# substring cues for the fallback, checked PII/file BEFORE secret (so "credit_card"
# and "api_key" don't both collapse to secret via the shared "key"/"card" tokens).
_PII_CUES = ("pii", "email", "phone", "ssn", "credit_card", "card")
_FILE_CUES = ("file", "paste", "source_code")
_SECRET_CUES = ("key", "token", "secret", "password", "credential", "jwt",
                "entropy", "db_url", "dsn", "private", "cert", "_pat", "api_key")

ACTIONS = ("passed", "redacted", "blocked")
SOURCES = ("proxy", "hook")


def categorize(finding_type: str) -> str:
    t = (finding_type or "").lower()
    if t in SECRET_TYPES:
        return "secret"
    if t in PII_TYPES:
        return "pii"
    if t in FILE_TYPES:
        return "file"
    # substring fallback — order matters: pii/file cues win over the broad secret set
    if any(c in t for c in _PII_CUES):
        return "pii"
    if any(c in t for c in _FILE_CUES) or t.endswith("_file"):
        return "file"
    if any(c in t for c in _SECRET_CUES):
        return "secret"
    return "other"


# Product name — SINGLE SOURCE OF TRUTH for the audit dir. Name ratified
# `leakproof` (worker-claude #389). The python namespace stays `leakproof` until
# the final mechanical rename sweep; this user-facing runtime path tracks the
# public name now. Other lanes (TUI etc.) MUST call audit_path() rather than
# hardcode a path, so writer (proxy/hook) and reader (TUI) never desync.
APP_NAME = "leakproof"

# Env overrides, highest precedence first (covers the rename in flight).
_AUDIT_ENV_VARS = ("LEAKPROOF_AUDIT_LOG", "AIRLOCK_AUDIT_LOG")


def audit_path() -> Path:
    """Resolve the audit log path (does not create it). Canonical for all lanes."""
    for env in _AUDIT_ENV_VARS:
        v = os.environ.get(env)
        if v:
            return Path(v).expanduser()
    return Path.home() / ".local" / "share" / APP_NAME / "audit.jsonl"


# --- models ----------------------------------------------------------------


@dataclass
class Finding:
    """One thing the scanner caught. Mirrors worker-2's scanner.Finding (#370)."""
    type: str
    span: list[int] = field(default_factory=lambda: [0, 0])
    severity: str = "high"
    reason: str = ""
    redaction: str = ""
    source: str = "rules"          # "rules" | "semantic"

    @property
    def category(self) -> str:
        return categorize(self.type)

    @classmethod
    def coerce(cls, f) -> "Finding":
        if isinstance(f, Finding):
            return f
        return cls(
            type=f.get("type", "other"),
            span=list(f.get("span", [0, 0])),
            severity=f.get("severity", "high"),
            reason=f.get("reason", ""),
            redaction=f.get("redaction", ""),
            source=f.get("source", "rules"),
        )


@dataclass
class AuditEvent:
    """One inspected outbound payload. This is the JSONL line shape."""
    source: str                              # "proxy" | "hook"
    action: str = "passed"                   # passed | redacted | blocked
    tool: str | None = None                  # "claude-code", "aider", "cursor"
    method: str = "POST"
    host: str | None = None                  # proxy: api.anthropic.com
    url: str | None = None                   # proxy: full outbound URL
    target: str | None = None                # hook: repo path / staged file
    findings: list[Finding] = field(default_factory=list)
    bytes_in: int = 0                        # payload size before redaction
    bytes_redacted: int = 0                  # bytes masked/removed
    preview: str | None = None               # already-redacted snippet for display
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    @property
    def n_findings(self) -> int:
        return len(self.findings)

    def count(self, category: str) -> int:
        return sum(1 for f in self.findings if f.category == category)

    # ---- serialization ----

    def to_dict(self) -> dict:
        d = asdict(self)
        d["n_findings"] = self.n_findings   # derived, but written for consumers
        return d

    def to_json(self) -> str:
        # ensure_ascii=False keeps redaction tokens / previews human-readable
        # in the log (still valid UTF-8 JSON).
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict) -> "AuditEvent":
        return cls(
            source=d.get("source", "proxy"),
            action=d.get("action", "passed"),
            tool=d.get("tool"),
            method=d.get("method", "POST"),
            host=d.get("host"),
            url=d.get("url"),
            target=d.get("target"),
            findings=[Finding.coerce(f) for f in (d.get("findings") or [])],
            bytes_in=int(d.get("bytes_in", 0)),
            bytes_redacted=int(d.get("bytes_redacted", 0)),
            preview=d.get("preview"),
            ts=float(d.get("ts", time.time())),
            id=d.get("id") or uuid.uuid4().hex[:12],
        )

    @classmethod
    def from_json(cls, line: str) -> "AuditEvent":
        return cls.from_dict(json.loads(line))


@dataclass
class Totals:
    """Rollup the TUI headlines with. The 'uncomfortable screenshot' numbers."""
    requests: int = 0
    secrets: int = 0
    pii: int = 0
    files: int = 0
    blocked: int = 0
    redacted: int = 0
    passed: int = 0
    bytes_in: int = 0
    bytes_protected: int = 0                 # bytes that would have left, stopped
    by_tool: dict[str, int] = field(default_factory=dict)
    by_source: dict[str, int] = field(default_factory=dict)

    @property
    def caught(self) -> int:
        """Total findings stopped (the big number)."""
        return self.secrets + self.pii + self.files


# --- writer ----------------------------------------------------------------


def record(event, path: Path | str | None = None) -> AuditEvent:
    """Append an event to the audit log. Accepts an AuditEvent, a dict, or
    kwargs-via-dict. Returns the AuditEvent. Used by proxy (L1) and hook.

    O_APPEND keeps each line write atomic, so concurrent proxy+hook writers
    don't interleave.
    """
    if isinstance(event, dict):
        event = AuditEvent.from_dict(event)
    p = Path(path).expanduser() if path else audit_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(event.to_json() + "\n")
    return event


# --- readers ---------------------------------------------------------------


def read_events(path: Path | str | None = None) -> list[AuditEvent]:
    """Read every event currently in the log (malformed lines skipped)."""
    p = Path(path).expanduser() if path else audit_path()
    if not p.exists():
        return []
    out: list[AuditEvent] = []
    with open(p, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(AuditEvent.from_json(line))
            except (json.JSONDecodeError, ValueError, KeyError):
                continue  # one bad line never kills the live view
    return out


def follow(path: Path | str | None = None, poll: float = 0.3,
           from_start: bool = True) -> Iterator[AuditEvent]:
    """Yield events as they are appended (like `tail -f`). Blocks forever.

    Survives the file not existing yet, truncation, and rotation. Partial
    (not-yet-newline-terminated) trailing writes are held until complete.
    """
    p = Path(path).expanduser() if path else audit_path()
    pos = 0 if from_start else None
    inode = None
    while True:
        try:
            st = p.stat()
        except FileNotFoundError:
            time.sleep(poll)
            continue
        if inode is None:
            inode = st.st_ino
            if pos is None:                  # start at current end
                pos = st.st_size
        if st.st_ino != inode or st.st_size < pos:   # rotated/truncated
            pos, inode = 0, st.st_ino
        if st.st_size > pos:
            with open(p, "r", encoding="utf-8") as fh:
                fh.seek(pos)
                # readline() (not `for line in fh`) so tell() is allowed
                while True:
                    line = fh.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        break                # partial line; wait for the rest
                    pos = fh.tell()
                    s = line.strip()
                    if not s:
                        continue
                    try:
                        yield AuditEvent.from_json(s)
                    except (json.JSONDecodeError, ValueError, KeyError):
                        continue
        time.sleep(poll)


# --- rollup ----------------------------------------------------------------


def aggregate(events) -> Totals:
    """Roll a list of events into the dashboard totals."""
    t = Totals()
    for ev in events:
        if isinstance(ev, dict):
            ev = AuditEvent.from_dict(ev)
        t.requests += 1
        t.bytes_in += ev.bytes_in
        t.secrets += ev.count("secret")
        t.pii += ev.count("pii")
        t.files += ev.count("file")
        if ev.action == "blocked":
            t.blocked += 1
            # a blocked payload would have left whole; count its full size
            t.bytes_protected += ev.bytes_in
        elif ev.action == "redacted":
            t.redacted += 1
            t.bytes_protected += ev.bytes_redacted
        else:
            t.passed += 1
        if ev.tool:
            t.by_tool[ev.tool] = t.by_tool.get(ev.tool, 0) + 1
        t.by_source[ev.source] = t.by_source.get(ev.source, 0) + 1
    return t
