"""Tests for the tripwire.hook surface (leakproof Surface B). Uses a FAKE scanner
matching worker-2's locked contract (#370) so this lane tests standalone."""
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

# src-layout: make `tripwire` importable without an install/build
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from tripwire import hook
from tripwire.hook import core

AWS = re.compile(r"AKIA[0-9A-Z]{16}")


def fake_scan(text, ctx=None):
    findings = []
    for m in AWS.finditer(text):
        if m.group(0) == "AKIAIOSFODNN7EXAMPLE":  # documented example key — never flag
            continue
        findings.append({
            "type": "aws_secret_key", "span": [m.start(), m.end()],
            "severity": "critical", "reason": "AWS access key id",
            "redaction": "‹aws_secret_key redacted›", "source": "rules",
        })
    if "john@example.com" in text:
        i = text.index("john@example.com")
        findings.append({
            "type": "pii_email", "span": [i, i + len("john@example.com")],
            "severity": "low", "reason": "email address",
            "redaction": "‹email redacted›", "source": "rules",
        })
    return findings


def fake_redact(text, findings):
    out = text
    for f in sorted(findings, key=lambda f: f["span"][0], reverse=True):
        s, e = f["span"]
        out = out[:s] + f["redaction"] + out[e:]
    return out


DIFF_WITH_KEY = (
    'diff --git a/config.py b/config.py\n--- /dev/null\n+++ b/config.py\n'
    '@@ -0,0 +1,2 @@\n+AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n+SAFE = "hello world"\n'
)
DIFF_EXAMPLE_ONLY = (
    'diff --git a/README b/README\n--- /dev/null\n+++ b/README\n'
    '@@ -0,0 +1 @@\n+use AKIAIOSFODNN7EXAMPLE as the placeholder\n'
)
DIFF_PII_ONLY = (
    'diff --git a/t.py b/t.py\n--- /dev/null\n+++ b/t.py\n'
    '@@ -0,0 +1 @@\n+owner = "john@example.com"\n'
)


def _git(args, cwd):
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True)


class TestParse(unittest.TestCase):
    def test_added_lines_with_linenos(self):
        added = core.parse_added_lines(DIFF_WITH_KEY)
        self.assertEqual(len(added), 2)
        self.assertEqual(added[0], ("config.py", 1, 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"'))
        self.assertEqual(added[1][1], 2)

    def test_ignores_headers(self):
        for _, _, text in core.parse_added_lines(DIFF_WITH_KEY):
            self.assertFalse(text.startswith("++"))


class TestCheck(unittest.TestCase):
    def _check(self, diff, **kw):
        lines = []
        code = hook.check(get_diff=lambda: diff, scan=fake_scan, redact=fake_redact,
                          out=lines.append, **kw)
        return code, "\n".join(lines)

    def test_blocks_on_critical(self):
        code, output = self._check(DIFF_WITH_KEY)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED", output)

    def test_preview_never_leaks_raw_secret(self):
        _, output = self._check(DIFF_WITH_KEY)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", output)
        self.assertIn("redacted", output)

    def test_example_key_is_not_flagged(self):
        code, output = self._check(DIFF_EXAMPLE_ONLY)
        self.assertEqual(code, 0)
        self.assertEqual(output, "")

    def test_pii_below_threshold_allows_in_block_mode(self):
        code, output = self._check(DIFF_PII_ONLY)
        self.assertEqual(code, 0)
        self.assertIn("below threshold", output)

    def test_low_threshold_blocks_pii(self):
        code, _ = self._check(DIFF_PII_ONLY, threshold="low")
        self.assertEqual(code, 1)

    def test_warn_mode_never_blocks(self):
        code, _ = self._check(DIFF_WITH_KEY, mode="warn")
        self.assertEqual(code, 0)

    def test_records_audit_event(self):
        events = []
        hook.check(get_diff=lambda: DIFF_WITH_KEY, scan=fake_scan,
                   redact=fake_redact, record=events.append, out=lambda *_: None)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["source"], "hook")
        self.assertEqual(ev["action"], "blocked")
        self.assertEqual(ev["n_findings"], 1)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", ev["preview"])
        for k in ("id", "ts", "source", "target", "action", "findings", "preview"):
            self.assertIn(k, ev)


class TestInstall(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        _git(["init", "-q"], self.dir)

    def _read(self, path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_install_cmd_returns_zero(self):
        self.assertEqual(hook.install(self.dir), 0)

    def test_install_creates_executable_hook(self):
        path = hook.install_hook(self.dir, command="python -m tripwire.hook")
        self.assertTrue(os.access(path, os.X_OK))
        self.assertIn("tripwire.hook", self._read(path))

    def test_install_backs_up_existing(self):
        hooks = os.path.join(self.dir, ".git", "hooks")
        os.makedirs(hooks, exist_ok=True)
        pc = os.path.join(hooks, "pre-commit")
        with open(pc, "w") as fh:
            fh.write("#!/bin/sh\necho mine\n")
        hook.install_hook(self.dir, force=True)
        self.assertIn("echo mine", self._read(pc + ".leakproof-backup"))

    def test_install_cmd_refuses_without_force_returns_one(self):
        hooks = os.path.join(self.dir, ".git", "hooks")
        os.makedirs(hooks, exist_ok=True)
        with open(os.path.join(hooks, "pre-commit"), "w") as fh:
            fh.write("#!/bin/sh\necho mine\n")
        self.assertEqual(hook.install(self.dir), 1)

    def test_uninstall_restores_backup(self):
        hooks = os.path.join(self.dir, ".git", "hooks")
        os.makedirs(hooks, exist_ok=True)
        pc = os.path.join(hooks, "pre-commit")
        with open(pc, "w") as fh:
            fh.write("#!/bin/sh\necho mine\n")
        hook.install_hook(self.dir, force=True)
        hook.uninstall(self.dir)
        self.assertIn("echo mine", self._read(pc))

    def test_uninstall_leaves_foreign_hook(self):
        hooks = os.path.join(self.dir, ".git", "hooks")
        os.makedirs(hooks, exist_ok=True)
        pc = os.path.join(hooks, "pre-commit")
        with open(pc, "w") as fh:
            fh.write("#!/bin/sh\necho not-ours\n")
        self.assertFalse(hook.uninstall_hook(self.dir))
        self.assertIn("not-ours", self._read(pc))


class TestRealGitCommit(unittest.TestCase):
    """End-to-end: an INSTALLED hook intercepts a real `git commit`. The hook execs
    a tiny runner wired with the fake scanner (stands in for the real scanner)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        _git(["init", "-q"], self.dir)
        _git(["config", "user.email", "t@t.co"], self.dir)
        _git(["config", "user.name", "t"], self.dir)
        src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
        runner = os.path.join(self.dir, "runner.py")
        with open(runner, "w") as fh:
            fh.write(textwrap.dedent(f"""
                import re, sys
                sys.path.insert(0, {src!r})
                from tripwire import hook
                from tripwire.hook import core
                AWS = re.compile(r'AKIA[0-9A-Z]{{16}}')
                def scan(t, ctx=None):
                    return [{{'type':'aws_secret_key','span':[m.start(),m.end()],
                             'severity':'critical','reason':'aws','redaction':'<redacted>',
                             'source':'rules'}} for m in AWS.finditer(t)]
                def redact(t, fs):
                    for f in sorted(fs, key=lambda f: f['span'][0], reverse=True):
                        s,e=f['span']; t=t[:s]+f['redaction']+t[e:]
                    return t
                sys.exit(hook.check(get_diff=lambda: core.real_staged_diff('.'),
                                    scan=scan, redact=redact, repo='.'))
            """))
        hook.install_hook(self.dir, command=f"{sys.executable} {runner}")

    def test_commit_with_secret_is_blocked(self):
        with open(os.path.join(self.dir, "s.py"), "w") as fh:
            fh.write('KEY = "AKIAABCDEFGHIJKLMNOP"\n')
        _git(["add", "."], self.dir)
        res = _git(["commit", "-m", "leak"], self.dir)
        self.assertNotEqual(res.returncode, 0, "commit should have been blocked")
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", res.stdout + res.stderr)

    def test_clean_commit_succeeds(self):
        with open(os.path.join(self.dir, "ok.py"), "w") as fh:
            fh.write('VALUE = 42\n')
        _git(["add", "."], self.dir)
        res = _git(["commit", "-m", "clean"], self.dir)
        self.assertEqual(res.returncode, 0, f"clean commit should pass: {res.stderr}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
