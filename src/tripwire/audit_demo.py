"""Generate a realistic demo audit log — the "money shot" data.

This lets the TUI (L3), landing page (L6), and Show HN demo be built and
screenshotted RIGHT NOW against real-shaped events, with zero dependency on a
running proxy or scanner.

Every "secret" below is OBVIOUSLY FAKE (EXAMPLE markers / zero-value strings) —
this file is committed to a repo, so it must contain no real credential. The
shapes are realistic; the values are not.

  python -m tripwire.audit_demo [path]      # writes the demo log
  from tripwire.audit_demo import generate   # programmatic

Wire-in note (worker-claude / CLI lane): expose as `airlock demo-log` ->
`tripwire.audit_demo.main`.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .audit import AuditEvent, Finding, audit_path, record

# A curated, deterministic sequence — better than RNG for a reproducible
# screenshot. ts is assigned at write time, evenly spaced ending "now".
#
# Each tuple: (source, tool, host/target, action, [findings], bytes_in,
#              bytes_redacted, preview)
_F = Finding  # brevity


def _scenario() -> list[AuditEvent]:
    return [
        AuditEvent(
            source="proxy", tool="claude-code", host="api.anthropic.com",
            url="https://api.anthropic.com/v1/messages", action="blocked",
            bytes_in=18_432, bytes_redacted=18_432,
            findings=[
                _F("aws_secret_key", [412, 452], "critical",
                   "AWS secret access key in request body",
                   "‹aws_secret_key redacted›"),
                _F("env_value", [980, 1024], "high",
                   "DB_PASSWORD from .env included in prompt context",
                   "DB_PASSWORD=‹redacted›"),
            ],
            preview="...deploy with AWS_SECRET_ACCESS_KEY=‹aws_secret_key redacted› "
                    "and DB_PASSWORD=‹redacted› to the...",
        ),
        AuditEvent(
            source="proxy", tool="cursor", host="api.openai.com",
            url="https://api.openai.com/v1/chat/completions", action="redacted",
            bytes_in=9_210, bytes_redacted=51,
            findings=[
                _F("openai_key", [120, 171], "critical",
                   "OpenAI API key (sk-) in src/client.py sent as context",
                   "sk-‹redacted›"),
            ],
            preview="const client = new OpenAI({ apiKey: 'sk-‹redacted›' })",
        ),
        AuditEvent(
            source="hook", tool="git", target="~/work/payments/.env",
            action="blocked", bytes_in=2_048, bytes_redacted=2_048,
            findings=[
                _F("stripe_key", [44, 88], "critical",
                   "Live Stripe secret key staged in .env",
                   "sk_live_‹redacted›"),
                _F("db_url", [110, 173], "high",
                   "Postgres connection string with inline password",
                   "postgres://user:‹redacted›@..."),
            ],
            preview="STRIPE_SECRET_KEY=sk_live_‹redacted›\nDATABASE_URL=postgres://user:‹redacted›@db...",
        ),
        AuditEvent(
            source="proxy", tool="aider", host="api.anthropic.com",
            url="https://api.anthropic.com/v1/messages", action="redacted",
            bytes_in=64_900, bytes_redacted=63_800,
            findings=[
                _F("source_file", [0, 63800], "medium",
                   "Entire file src/internal/billing.py (1,812 lines) sent as context",
                   "‹full file billing.py redacted — 1,812 lines›"),
            ],
            preview="# src/internal/billing.py ‹full file redacted — 1,812 lines, 63.8 KB›",
        ),
        AuditEvent(
            source="proxy", tool="claude-code", host="api.anthropic.com",
            url="https://api.anthropic.com/v1/messages", action="redacted",
            bytes_in=7_700, bytes_redacted=40,
            findings=[
                _F("github_token", [300, 340], "critical",
                   "GitHub personal access token (ghp_) in shell history pasted into prompt",
                   "ghp_‹redacted›"),
            ],
            preview="$ gh auth login --with-token ghp_‹redacted›",
        ),
        AuditEvent(
            source="proxy", tool="cursor", host="api.openai.com",
            url="https://api.openai.com/v1/chat/completions", action="redacted",
            bytes_in=5_120, bytes_redacted=120,
            findings=[
                _F("pii_email", [88, 109], "medium",
                   "Customer email address in a test fixture sent to cloud",
                   "‹email redacted›"),
                _F("credit_card", [210, 229], "high",
                   "Test fixture contains a Luhn-valid card number",
                   "‹card redacted›"),
            ],
            preview='{ "email": "‹email redacted›", "card": "‹card redacted›" }',
        ),
        AuditEvent(
            source="proxy", tool="aider", host="api.openai.com",
            url="https://api.openai.com/v1/chat/completions", action="blocked",
            bytes_in=3_300, bytes_redacted=3_300,
            findings=[
                _F("private_key", [0, 1704], "critical",
                   "RSA private key (-----BEGIN PRIVATE KEY-----) in prompt",
                   "‹private_key redacted›"),
            ],
            preview="-----BEGIN PRIVATE KEY----- ‹redacted› -----END PRIVATE KEY-----",
        ),
        # A few clean pass-throughs so the ratio looks real (not every call leaks).
        AuditEvent(source="proxy", tool="claude-code", host="api.anthropic.com",
                   url="https://api.anthropic.com/v1/messages", action="passed",
                   bytes_in=4_096, findings=[]),
        AuditEvent(source="proxy", tool="aider", host="api.openai.com",
                   url="https://api.openai.com/v1/chat/completions", action="passed",
                   bytes_in=2_900, findings=[]),
        AuditEvent(source="proxy", tool="cursor", host="api.openai.com",
                   url="https://api.openai.com/v1/chat/completions", action="passed",
                   bytes_in=6_400, findings=[]),
    ]


def generate(path: Path | str | None = None, *, span_seconds: int = 180) -> Path:
    """Write the demo scenario to the audit log. Returns the path.

    Truncates any existing log at `path` first so the demo is reproducible.
    Timestamps are evenly spaced over the last `span_seconds`, ending now.
    """
    import time as _time

    events = _scenario()
    now = _time.time()
    n = len(events)
    step = span_seconds / max(n - 1, 1)
    for i, ev in enumerate(events):
        ev.ts = now - (n - 1 - i) * step

    p = Path(path).expanduser() if path else audit_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("")  # reset for reproducibility
    for ev in events:
        record(ev, path=p)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    path = argv[0] if argv else None
    p = generate(path)
    n = len(_scenario())
    print(f"wrote {n} demo events -> {p}")
    print("view live:  leakproof watch      (or: python -m tripwire.tui)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
