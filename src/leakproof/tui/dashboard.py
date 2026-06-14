"""leakproof TUI — the live "what just tried to leave" dashboard.

This is the Show-HN screenshot: a terminal that fills in real time with every
secret / .env value / PII / full-file blob an AI editor (or a git commit) tried
to ship off the machine — each caught and redacted or blocked before it left.

Pure stdlib ANSI: no curses, no rich, no deps. Renders identically over SSH, in
an asciinema recording, and in a `uvx leakproof watch` one-liner — and a zero-dep
security tool is on-brand (nothing to audit, instant install).

L3 is co-owned: worker-opus-1 owns `audit.py` (the log + Totals), this file owns
the rendering. It consumes the audit module's *locked* API only:
    audit.read_events(path) -> [AuditEvent]
    audit.follow(path, from_start=False) -> Iterator[AuditEvent]
    audit.aggregate(events) -> Totals
    audit.audit_path() -> canonical path
Rendering is split from the loop so it's testable without a TTY:
    render_frame(events) -> str   # pure, deterministic
    watch(audit_path=None) -> int # tails the log, repaints per event
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from collections import Counter

from leakproof import audit


# --- ANSI ----------------------------------------------------------------------

class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    CYAN = "\033[36m"; GREY = "\033[90m"
    BG_RED = "\033[41m"; WHITE = "\033[97m"


_NOCOLOR = False


def _c(code: str, text: str) -> str:
    return text if _NOCOLOR else f"{code}{text}{C.RESET}"


_ACTION_STYLE = {
    "blocked": (C.BG_RED + C.WHITE + C.BOLD, "BLOCKED "),
    "redacted": (C.YELLOW + C.BOLD, "REDACTED"),
    "passed": (C.GREEN, "passed  "),
}
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEV_COLOR = {"critical": C.BG_RED + C.WHITE, "high": C.RED, "medium": C.YELLOW,
              "low": C.GREY, "info": C.GREY}


def _fmt_bytes(n: float) -> str:
    if n < 1024:
        return f"{int(n)}B"
    for unit in ("KB", "MB", "GB"):
        n /= 1024
        if n < 1024 or unit == "GB":
            return f"{n:.1f}{unit}"
    return f"{n:.1f}GB"


def _hms(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def _truncate(s: str, n: int) -> str:
    s = (s or "").replace("\n", " ").replace("\r", " ")
    return s if len(s) <= n else s[: max(0, n - 1)] + "…"


def _top_severity(ev) -> str:
    """Highest severity across an event's findings (Finding objects or dicts)."""
    best = ""
    best_rank = -1
    for f in ev.findings:
        sev = getattr(f, "severity", None) if not isinstance(f, dict) else f.get("severity")
        r = _SEV_RANK.get(sev or "", -1)
        if r > best_rank:
            best, best_rank = sev or "", r
    return best


def _ftype(f) -> str:
    return (f.get("type") if isinstance(f, dict) else getattr(f, "type", None)) or "—"


# --- frame rendering -----------------------------------------------------------

def render_frame(events, *, width: int | None = None, limit: int = 15) -> str:
    """Build the full dashboard frame from a list of AuditEvents. Pure: same
    inputs -> same string. Totals come from the audit module (single source)."""
    events = list(events)
    width = width or shutil.get_terminal_size((100, 30)).columns
    width = max(60, min(width, 160))
    t = audit.aggregate(events)
    lines: list[str] = []

    # header banner
    lines.append(_c(C.CYAN + C.BOLD, "  LEAKPROOF  —  nothing leaves the building  ".ljust(width)))

    # the shock number
    caught = t.caught
    if caught:
        unit = "secret" if caught == 1 else "secrets"
        lines.append(_c(C.RED + C.BOLD,
                        f"\U0001f512  {caught} {unit} stopped from leaving your machine"))
    else:
        lines.append(_c(C.GREEN + C.BOLD, "\U0001f512  leakproof armed — watching outbound traffic"))
    sub = (f"{t.requests} request{'s' if t.requests != 1 else ''} inspected   "
           f"•  {t.blocked} blocked  •  {t.redacted} redacted  •  {t.passed} clean   "
           f"•  {_fmt_bytes(t.bytes_protected)} kept in")
    lines.append(_c(C.GREY, sub))

    # category + type breakdown
    cat = f"secrets {t.secrets}   pii {t.pii}   files {t.files}"
    types = Counter(_ftype(f) for ev in events for f in ev.findings)
    if types:
        chips = "   ".join(f"{ty} ×{n}" for ty, n in types.most_common(6))
        lines.append(_c(C.DIM, f"  {cat}      {chips}"))
    lines.append(_c(C.GREY, "─" * width))

    # column header
    hdr = f"{'time':<8}  {'source':<6}  {'tool':<12}  {'action':<8}  {'what leakproof caught':<30}  detail"
    lines.append(_c(C.BOLD, _truncate(hdr, width)))

    # recent catches, newest first
    recent = sorted(events, key=lambda e: e.ts, reverse=True)[:limit]
    if not recent:
        lines.append(_c(C.DIM, "  (nothing yet — run a tool through `leakproof run -- <tool>`)"))
    for e in recent:
        style, label = _ACTION_STYLE.get(e.action, (C.RESET, (e.action[:8]).ljust(8)))
        sev = _top_severity(e)
        ftype = _ftype(e.findings[0]) if e.findings else "—"
        sev_s = _c(_SEV_COLOR.get(sev, C.GREY), f"[{sev}]") if sev else ""
        what = _truncate(f"{ftype} {sev_s}".rstrip(), 38)
        where = e.url or e.host or e.target or ""
        detail = _truncate(e.preview or where, max(12, width - 78))
        row = (f"{_hms(e.ts):<8}  {e.source:<6}  {_truncate(e.tool or '—', 12):<12}  "
               f"{_c(style, label)}  {what:<30}  {_c(C.DIM, detail)}")
        lines.append(row)

    # per-tool footer
    if t.by_tool:
        lines.append(_c(C.GREY, "─" * width))
        tools = "   ".join(f"{tool}: {n}" for tool, n in
                           sorted(t.by_tool.items(), key=lambda kv: -kv[1]))
        lines.append(_c(C.DIM, "  by tool:  " + tools))
    return "\n".join(lines)


# --- live loop -----------------------------------------------------------------

def watch(audit_path=None, *, limit: int = 15, refresh: float = 1.0) -> int:
    """Tail the audit log and repaint on every new event (+ a heartbeat so
    relative times stay fresh). Ctrl-C exits cleanly. Returns a process exit
    code so the CLI can dispatch `tui.watch(path)` directly."""
    path = audit_path or audit.audit_path()
    events = audit.read_events(path)
    feed = audit.follow(path, from_start=False)
    last_paint = 0.0

    def paint() -> None:
        nonlocal last_paint
        sys.stdout.write("\033[H\033[2J")        # home + clear
        sys.stdout.write(render_frame(events, limit=limit))
        sys.stdout.write("\n" + _c(C.DIM,
                         "  ctrl-c to stop  •  leakproof runs locally — this view never leaves your box\n"))
        sys.stdout.flush()
        last_paint = time.time()

    sys.stdout.write("\033[2J")
    paint()
    try:
        while True:
            got = False
            for ev in _drain(feed, budget=0.2):
                events.append(ev)
                got = True
            if got or (time.time() - last_paint) >= refresh:
                paint()
            time.sleep(0.05)
    except KeyboardInterrupt:
        sys.stdout.write("\n" + _c(C.CYAN, "leakproof disarmed. stay safe.\n"))
        sys.stdout.flush()
    return 0


def _drain(feed, *, budget: float):
    """Pull whatever events the follow() generator has ready within a time
    budget (follow() sleeps internally; cap how long we sit in it per frame)."""
    start = time.time()
    while time.time() - start < budget:
        try:
            yield next(feed)
        except StopIteration:
            return


# --- cli (standalone) ----------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    global _NOCOLOR
    p = argparse.ArgumentParser("leakproof-watch", description="Live leakproof leak dashboard.")
    p.add_argument("--audit-log", default=None,
                   help="path to audit.jsonl (default: audit.audit_path())")
    p.add_argument("--once", action="store_true", help="render the current log once and exit")
    p.add_argument("--demo", action="store_true",
                   help="(re)generate the demo audit log, then render once")
    p.add_argument("--limit", type=int, default=15, help="rows of recent catches to show")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)
    _NOCOLOR = args.no_color

    if args.demo:
        try:
            from leakproof import audit_demo
            audit_demo.main([])          # seeds the default-path demo log
        except Exception as exc:          # demo is best-effort; render whatever exists
            sys.stderr.write(f"(demo-log generator unavailable: {exc})\n")
        print(render_frame(audit.read_events(args.audit_log), limit=args.limit))
        return 0

    if args.once:
        print(render_frame(audit.read_events(args.audit_log), limit=args.limit))
        return 0
    return watch(args.audit_log, limit=args.limit)


if __name__ == "__main__":
    raise SystemExit(main())
