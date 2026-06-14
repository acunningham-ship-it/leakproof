"""airlock pre-commit hook — core logic.

Owner: worker-opus (hook/ surface). Surface B of the leak-firewall: block secrets/
PII from ever hitting git. Pure-ish, dependency-injected so it unit-tests with no
git, no scanner, no audit log.

LOCKED contracts this builds against:
  scanner.scan(text, ctx=None) -> list[Finding]          # worker-2 #370
  scanner.redact(text, findings) -> str                  # worker-2 #370
  Finding = {type, span:[s,e], severity, reason, redaction, source}
  audit.record(event)                                    # opus-1 #375 / opus-4 #371
  AuditEvent = {id, ts, source:"hook", tool, method, host, url, target,
                action:"blocked"|"allowed", findings, n_findings, bytes_in, preview}
"""
from __future__ import annotations

import subprocess
import time
import uuid
from typing import Callable, Iterable, Optional

# --- severity ----------------------------------------------------------------
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _rank(sev: str) -> int:
    return SEVERITY_RANK.get(str(sev).lower(), 0)


# --- staged diff parsing -----------------------------------------------------
def real_staged_diff(repo: str = ".") -> str:
    """The default get_diff: staged changes only, no context lines (added lines only)."""
    out = subprocess.run(
        ["git", "diff", "--cached", "--no-color", "--unified=0"],
        cwd=repo, capture_output=True, text=True,
    )
    return out.stdout


def parse_added_lines(diff_text: str) -> list[tuple[str, int, str]]:
    """Return [(file_path, new_line_no, added_text), ...] for every '+' line in a
    unified diff. Ignores file headers (+++), removed lines, and context."""
    added: list[tuple[str, int, str]] = []
    current_file = "?"
    new_lineno = 0
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            current_file = "/dev/null" if path == "/dev/null" else path
            continue
        if raw.startswith("--- "):
            continue
        if raw.startswith("@@"):
            # @@ -a,b +c,d @@  -> new hunk starts at line c
            try:
                plus = raw.split("+", 1)[1]
                start = plus.split(" ", 1)[0].split(",", 1)[0]
                new_lineno = int(start)
            except (IndexError, ValueError):
                new_lineno = 0
            continue
        if raw.startswith("+"):
            added.append((current_file, new_lineno, raw[1:]))
            new_lineno += 1
        elif raw.startswith(" "):
            new_lineno += 1
        # removed lines ('-') do not advance the new-file counter
    return added


# --- the hook run ------------------------------------------------------------
def _noop_record(event: dict) -> None:
    pass


def check(
    *,
    get_diff: Callable[[], str],
    scan: Callable[..., list],
    redact: Callable[[str, list], str],
    record: Callable[[dict], None] = _noop_record,
    threshold: str = "high",
    mode: str = "block",          # "block" | "warn"
    repo: str = ".",
    out: Callable[[str], None] = print,
) -> int:
    """Scan the staged diff; block (exit 1) if any finding is >= threshold in block
    mode. Returns the process exit code (0 = allow commit, 1 = block)."""
    diff = get_diff()
    added = parse_added_lines(diff)

    findings: list[dict] = []
    # map line-key -> (text, [findings]) so we can build a redacted preview per line
    per_line: dict[tuple, tuple[str, list]] = {}
    for path, lineno, text in added:
        line_findings = scan(text)
        if not line_findings:
            continue
        per_line[(path, lineno)] = (text, line_findings)
        for f in line_findings:
            findings.append({**f, "file": path, "line": lineno})

    blocking = [f for f in findings if _rank(f.get("severity", "low")) >= _rank(threshold)]
    action = "blocked" if (mode == "block" and blocking) else "allowed"

    # build a preview that NEVER contains a raw secret (DLP-correct)
    preview_lines: list[str] = []
    for (path, lineno), (text, lfs) in per_line.items():
        redacted = redact(text, lfs)
        preview_lines.append(f"{path}:{lineno}: {redacted.strip()}")
    preview = "\n".join(preview_lines[:20])

    record({
        "id": uuid.uuid4().hex,
        "ts": time.time(),
        "source": "hook",
        "tool": None,
        "method": None,
        "host": None,
        "url": None,
        "target": repo,
        "action": action,
        "findings": findings,
        "n_findings": len(findings),
        "bytes_in": sum(len(t) for _, _, t in added),
        "preview": preview,
    })

    _report(out, findings, blocking, action, mode, per_line, redact)
    return 1 if action == "blocked" else 0


def run(repo: str = ".", *, threshold: str = "high", mode: str = "block") -> int:
    """CLI/git entry point (`leakproof hook run`). Wires the real scanner + audit
    log, scans the staged diff, returns the process exit code. Degrades to a clean
    pass (exit 0) with a warning if the scanner lane hasn't landed yet, so a
    half-built tree never blocks the user's commits."""
    try:
        from ..scanner import scan, redact  # type: ignore
    except Exception:
        try:
            from scanner import scan, redact  # type: ignore  (flat layout / dev)
        except Exception:
            print("  leakproof: scanner not installed yet — skipping (commit allowed).")
            return 0

    try:
        from ..audit import record  # type: ignore
    except Exception:
        record = _noop_record

    return check(
        get_diff=lambda: real_staged_diff(repo),
        scan=scan, redact=redact, record=record,
        threshold=threshold, mode=mode, repo=repo,
    )


def _report(out, findings, blocking, action, mode, per_line, redact) -> None:
    if not findings:
        return
    out("")
    out("  leakproof — leak firewall (pre-commit)")
    out("  " + "-" * 44)
    for (path, lineno), (text, lfs) in per_line.items():
        redacted = redact(text, lfs).strip()
        kinds = ", ".join(sorted({f.get("type", "?") for f in lfs}))
        sev = max((f.get("severity", "low") for f in lfs), key=_rank)
        out(f"  [{sev:>8}] {path}:{lineno}  ({kinds})")
        out(f"             {redacted}")
    out("")
    if action == "blocked":
        out(f"  ✖ commit BLOCKED — {len(blocking)} finding(s) at/above threshold.")
        out("    Remove the secret(s) or, if this is a false positive, run:")
        out("      git commit --no-verify   (bypasses the hook)")
    else:
        out(f"  ⚠ {len(findings)} finding(s) below threshold — commit allowed (warn mode).")
    out("")
