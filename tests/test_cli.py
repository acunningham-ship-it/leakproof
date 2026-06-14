"""Tests for the leakproof CLI lane (owner: worker-claude).

Covers dispatch, exit codes, graceful degradation when a lane isn't implemented,
and the scan path against scanner.scan() / scanner.redact() (the locked seam).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from leakproof import cli  # noqa: E402

# Findings are plain dicts per worker-2's locked scanner contract.
def _finding(**kw):
    base = {"type": "secret", "span": [0, 4], "severity": "high",
            "reason": "test", "redaction": "***", "source": "rules"}
    base.update(kw)
    return base


def test_help_flag_exits_zero(capsys):
    # argparse's built-in -h raises SystemExit(0) after printing help
    with pytest.raises(SystemExit) as exc:
        cli.main(["-h"])
    assert exc.value.code == 0
    assert "leakproof" in capsys.readouterr().out.lower()


def test_no_args_prints_help():
    assert cli.main([]) == 0


def test_version():
    assert cli.main(["version"]) == 0
    assert cli.main(["-V"]) == 0


def test_scan_no_paths_errors():
    assert cli.main(["scan"]) == 1


def test_scan_clean_file(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text("print('hello world')\n")
    # scanner stub returns no findings -> exit 0
    assert cli.main(["scan", str(f)]) == 0


def test_scan_missing_file():
    assert cli.main(["scan", "/no/such/file/xyz"]) == 1


def test_scan_reports_leak(tmp_path, monkeypatch):
    """When scanner.scan finds something, scan exits 2."""
    f = tmp_path / "leak.env"
    f.write_text("AWS_SECRET=AKIAIOSFODNN7EXAMPLE\n")

    def fake_scan(text, context=None):
        return [_finding(type="aws_access_key", span=[11, 31], severity="critical",
                         reason="looks like an AWS access key", redaction="AWS_KEY_***")]

    monkeypatch.setattr("leakproof.scanner.scan", fake_scan)
    assert cli.main(["scan", str(f)]) == 2


def test_scan_low_severity_under_threshold_exits_zero(tmp_path, monkeypatch):
    """A low-sev finding (e.g. vendor_test_key) lists but does NOT fail by default."""
    f = tmp_path / "t.py"
    f.write_text("STRIPE=sk_test_abc\n")
    monkeypatch.setattr("leakproof.scanner.scan",
                        lambda text, context=None: [_finding(type="vendor_test_key", severity="low")])
    assert cli.main(["scan", str(f)]) == 0           # default --fail-on medium
    assert cli.main(["scan", "--fail-on", "low", str(f)]) == 2  # opt-in stricter


def test_run_without_command_errors():
    assert cli.main(["run"]) == 1


def test_lane_not_ready_is_graceful(monkeypatch):
    """A subcommand whose lane fn is missing returns 1, never raises."""
    # adapters.run doesn't exist yet -> graceful 1
    assert cli.main(["run", "--", "claude"]) == 1


def test_demo_log_graceful_when_absent():
    # audit_demo lane lands separately; until then demo-log degrades, never raises
    assert cli.main(["demo-log"]) in (0, 1)


def test_demo_log_calls_generator(monkeypatch):
    calls = {}

    def fake_main(argv=None):
        # cli passes [] so audit_demo never grabs sys.argv (opus-5's bug fix)
        calls["argv"] = argv
        return 0

    import types as _t
    mod = _t.ModuleType("leakproof.audit_demo")
    mod.main = fake_main
    monkeypatch.setitem(sys.modules, "leakproof.audit_demo", mod)
    assert cli.main(["demo-log"]) == 0
    assert calls.get("argv") == []


def test_semantic_off_by_default():
    import os
    cli.main(["version"])
    assert os.environ.get("LEAKPROOF_SEMANTIC") == "0"   # rules-only default
    cli.main(["--semantic", "version"])
    assert os.environ.get("LEAKPROOF_SEMANTIC") == "1"   # opt-in


def test_print_findings_empty(capsys):
    cli.print_findings([])
    assert "no leaks" in capsys.readouterr().out.lower()


def test_print_findings_nonempty(capsys):
    cli.print_findings([_finding(type="github_pat", span=[0, 10], severity="high",
                                 reason="GitHub token", redaction="GH_***")])
    out = capsys.readouterr().out
    assert "github_pat" in out and "leak" in out.lower()


def test_print_findings_tolerates_partial_dict(capsys):
    # defensive: a finding missing optional keys must not crash the renderer
    cli.print_findings([{"type": "x", "span": [0, 1], "severity": "low"}])
    assert "x" in capsys.readouterr().out
