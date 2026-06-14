"""Tests for leakproof.tui dashboard rendering. stdlib unittest, no deps.

Builds events with the real audit module types so the render stays honest to
the locked AuditEvent/Finding/Totals contract worker-opus-1 owns.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from leakproof import audit                       # noqa: E402
from leakproof.tui import dashboard, render_frame  # noqa: E402

dashboard._NOCOLOR = True                         # deterministic text for assertions


def _ev(action="redacted", tool="claude-code", ftype="aws_secret_key",
        severity="critical", category_bytes=2048, **kw):
    f = audit.Finding(type=ftype, span=[0, 10], severity=severity,
                      reason="test", redaction="‹redacted›")
    return audit.AuditEvent(source=kw.get("source", "proxy"), action=action, tool=tool,
                            host="api.anthropic.com", url="https://api.anthropic.com/v1/messages",
                            findings=[f], bytes_in=category_bytes,
                            bytes_redacted=kw.get("bytes_redacted", 32),
                            preview=kw.get("preview", "AWS_SECRET=‹redacted›"))


class TestRender(unittest.TestCase):
    def test_empty_armed_state(self):
        out = render_frame([], width=100)
        self.assertIn("LEAKPROOF", out)
        self.assertIn("armed", out)
        self.assertIn("nothing yet", out)

    def test_single_catch_headline(self):
        out = render_frame([_ev()], width=100)
        self.assertIn("1 secret stopped", out)
        self.assertIn("claude-code", out)
        self.assertIn("aws_secret_key", out)
        self.assertIn("REDACTED", out)

    def test_pluralization_and_totals(self):
        events = [_ev(), _ev(action="blocked", tool="cursor", ftype="private_key")]
        out = render_frame(events, width=120)
        self.assertIn("2 secrets stopped", out)
        self.assertIn("1 blocked", out)
        self.assertIn("1 redacted", out)
        self.assertIn("BLOCKED", out)

    def test_never_shows_raw_secret(self):
        # preview is the already-redacted snippet; the raw secret must not appear
        ev = _ev(preview="AWS_SECRET=‹redacted›")
        out = render_frame([ev], width=120)
        self.assertIn("‹redacted›", out)
        self.assertNotIn("AKIA", out)

    def test_pii_and_file_categories(self):
        events = [
            _ev(ftype="email", severity="medium"),         # pii bucket
            _ev(ftype="full_file", severity="high"),        # file bucket
        ]
        out = render_frame(events, width=120)
        self.assertIn("pii 1", out)
        self.assertIn("files 1", out)

    def test_hook_source_renders(self):
        ev = audit.AuditEvent(source="hook", action="blocked", target="~/repo (pre-commit)",
                              findings=[audit.Finding(type="stripe_key", severity="critical")],
                              preview="STRIPE=‹redacted›")
        out = render_frame([ev], width=120)
        self.assertIn("hook", out)
        self.assertIn("stripe_key", out)

    def test_limit_caps_rows(self):
        events = [_ev() for _ in range(40)]
        out = render_frame(events, width=120, limit=5)
        # header + 5 data rows worth of timestamps; count action labels
        self.assertLessEqual(out.count("REDACTED"), 5)

    def test_watch_once_reads_log(self):
        d = tempfile.mkdtemp(prefix="leakproof-tui-")
        path = os.path.join(d, "audit.jsonl")
        audit.record(_ev(), path=path)
        audit.record(_ev(action="blocked", ftype="github_token"), path=path)
        out = render_frame(audit.read_events(path), width=120)
        self.assertIn("2 secrets stopped", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
