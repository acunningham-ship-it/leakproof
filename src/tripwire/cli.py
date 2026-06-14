"""tripwire CLI — OWNER: worker-claude (lane: cli + packaging).

The single `tripwire` entry point. Routes to the lane modules, which it imports
lazily so the CLI runs today and each subcommand lights up the moment its lane
lands. Every lane just needs to expose the small entry function documented here.

Subcommands + the entry-point contract each lane implements:
  tripwire scan <path...>     scanner.scan(text, ctx) / scanner.redact(text, findings)   [worker-2]
  tripwire run -- <tool>...    adapters.run(tool, argv, proxy_url) -> int                 [adapters + proxy]
  tripwire proxy               proxy.serve(host, port) -> int                              [worker-opus-5]
  tripwire watch               tui.watch(audit_path=None) -> int                           [worker-opus-2]
  tripwire install-hook        hook.install(repo=".") -> int / hook.uninstall(repo=".")    [hook surface]
  tripwire version

Exit codes: 0 ok / no leaks · 1 usage or runtime error · 2 leaks found (scan/hook).
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Callable

from . import __version__

# Findings are plain dicts (worker-2's locked scanner contract — NOT a dataclass):
#   {"type": str, "span": [start,end], "severity": "critical|high|medium|low",
#    "reason": str, "redaction": str, "source": "rules"|"semantic"}
# We read defensively with .get() so optional keys never crash the renderer.

# ---------------------------------------------------------------------------
# pretty output (tty-aware, zero deps)

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "yellow": "\033[33m", "green": "\033[32m",
    "cyan": "\033[36m", "magenta": "\033[35m",
}
_SEV_COLOR = {
    "low": "cyan", "medium": "yellow", "high": "red", "critical": "magenta",
}


def _color_enabled(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


def _c(text: str, color: str, stream=sys.stdout) -> str:
    if not _color_enabled(stream):
        return text
    return f"{_C.get(color, '')}{text}{_C['reset']}"


def print_findings(findings: list, source: str = "") -> None:
    """Shared findings renderer. findings = list of scanner dicts (locked contract)."""
    if not findings:
        print(_c("✓ no leaks found", "green"))
        return
    hdr = f"⚠ {len(findings)} potential leak(s)"
    if source:
        hdr += f" in {source}"
    print(_c(hdr, "red"))
    for f in findings:
        sev_str = str(f.get("severity", "medium")).lower()
        sev = _c(sev_str.upper().ljust(8), _SEV_COLOR.get(sev_str, "yellow"))
        span = f.get("span") or [0, 0]
        loc = _c(f"@{span[0]}:{span[1]}", "dim")
        det = f.get("source") or f.get("detector") or "rules"
        print(f"  {sev} {_c(str(f.get('type', '?')), 'bold')} {loc}  {f.get('reason', '')}")
        red = f.get("redaction") or ""
        if red:
            print(f"           {_c(red, 'dim')}  [{det}]")


# ---------------------------------------------------------------------------
# lane bridge — import a lane module + entry fn lazily, with a clear message
# if that lane hasn't landed yet (so the CLI never hard-crashes mid-build).

def _lane(modname: str, fn: str, owner: str) -> Callable | None:
    try:
        mod = __import__(f"tripwire.{modname}", fromlist=[fn])
    except Exception as e:  # noqa: BLE001 - surface any import error cleanly
        print(_c(f"tripwire: lane '{modname}' failed to import ({e})", "red"), file=sys.stderr)
        return None
    impl = getattr(mod, fn, None)
    if impl is None:
        print(
            _c(f"tripwire: `{modname}.{fn}()` not implemented yet "
               f"(lane owner: {owner}). The CLI is wired; the lane is in progress.",
               "yellow"),
            file=sys.stderr,
        )
        return None
    return impl


# severity ranking (worker-2's emitted set: critical/high/medium/low) — used to
# decide exit codes so `scan` fails CI only on real leaks, not low-sev test keys.
_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_rank(sev) -> int:
    return _SEV_RANK.get(str(sev).lower(), 2)


# ---------------------------------------------------------------------------
# subcommands

def cmd_scan(args: argparse.Namespace) -> int:
    if not args.path:
        print("tripwire scan: give one or more file paths", file=sys.stderr)
        return 1
    scan = _lane("scanner", "scan", "worker-2")
    if scan is None:
        return 1
    redact = _lane("scanner", "redact", "worker-2") if args.show_redacted else None
    threshold = _sev_rank(args.fail_on)
    blocked = False  # any finding at/above the fail-on threshold
    for path in args.path:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            print(_c(f"tripwire: cannot read {path}: {e}", "red"), file=sys.stderr)
            return 1
        findings = scan(text, {"path": path})
        print(_c(f"\n{path}", "bold"))
        print_findings(findings, source=path)
        blocked = blocked or any(_sev_rank(f.get("severity")) >= threshold for f in findings)
        if args.show_redacted and findings and redact is not None:
            print(_c("--- redacted ---", "dim"))
            print(redact(text, findings))
    # exit 2 = leaks at/above --fail-on (CI-friendly); 0 = clean or only sub-threshold
    return 2 if blocked else 0


def _split_host_port(url: str) -> tuple[str, int]:
    """Parse host/port from a proxy URL like http://127.0.0.1:8747."""
    from urllib.parse import urlparse
    u = urlparse(url)
    return (u.hostname or "127.0.0.1", u.port or 8747)


def _import_proxy():
    """Import the proxy lane, or return None with a clear hint (needs aiohttp extra)."""
    try:
        from . import proxy  # noqa: PLC0415
        return proxy
    except ImportError as e:
        if "aiohttp" in str(e):
            print(_c("tripwire: the proxy needs aiohttp — install it with "
                     "`uvx 'leakproof[proxy]'` (or `pip install 'leakproof[proxy]'`).", "yellow"),
                  file=sys.stderr)
        else:
            print(_c(f"tripwire: proxy lane unavailable ({e}).", "yellow"), file=sys.stderr)
        return None


def cmd_run(args: argparse.Namespace) -> int:
    # argparse.REMAINDER keeps a leading "--"; drop it so cmd[0] is the tool.
    cmd = [a for a in args.cmd if a != "--"] if args.cmd else []
    if not cmd:
        print("tripwire run: nothing to run. usage: tripwire run -- <tool> [args...]",
              file=sys.stderr)
        return 1
    run = _lane("adapters", "run", "adapters surface")
    if run is None:
        return 1
    tool, *rest = cmd

    # cli↔proxy seam (opus-5's shipped API): start the proxy on a daemon thread,
    # point the child at bp.base_url, stop it when the child exits. --no-proxy skips
    # auto-start (you ran `tripwire proxy` yourself / one's already up at --proxy-url).
    bp = None
    target = args.proxy_url
    if not args.no_proxy:
        proxy = _import_proxy()
        start_bg = getattr(proxy, "start_background", None) if proxy else None
        if start_bg is not None:
            host, port = _split_host_port(args.proxy_url)
            try:
                bp = start_bg(host, port, mode=args.mode)
                target = getattr(bp, "base_url", args.proxy_url)
            except Exception as e:  # noqa: BLE001
                print(_c(f"tripwire: could not start proxy ({e}); assuming one is "
                         f"already running at {args.proxy_url}", "yellow"), file=sys.stderr)
                bp = None
        elif proxy is not None:
            print(_c(f"tripwire: proxy.start_background not found — pointing {tool} at "
                     f"{args.proxy_url} (start it with `tripwire proxy`).", "yellow"),
                  file=sys.stderr)
    try:
        # adapters.run expects argv = the FULL command (argv[0] is the tool binary it
        # execs); `cmd` is [tool, *rest]. `tool` stays the canonical key for env recipes.
        return int(run(tool=tool, argv=cmd, proxy_url=target))
    except FileNotFoundError as e:
        # tool binary not on PATH — adapters raises by design; fail gracefully, no traceback
        print(_c(f"tripwire run: {e}", "red"), file=sys.stderr)
        return 1
    finally:
        stop = getattr(bp, "stop", None)
        if callable(stop):
            try:
                stop()
            except Exception:  # noqa: BLE001
                pass


def cmd_proxy(args: argparse.Namespace) -> int:
    proxy = _import_proxy()
    serve = getattr(proxy, "serve", None) if proxy else None
    if serve is None:
        if proxy is not None:
            print(_c("tripwire: proxy.serve not implemented yet (lane owner: worker-opus-5)",
                     "yellow"), file=sys.stderr)
        return 1
    return int(serve(args.host, args.port, mode=args.mode))


def cmd_watch(args: argparse.Namespace) -> int:
    watch = _lane("tui", "watch", "worker-opus-2")
    if watch is None:
        return 1
    return int(watch(audit_path=args.audit_path))


def cmd_install_hook(args: argparse.Namespace) -> int:
    fn = "uninstall" if args.uninstall else "install"
    impl = _lane("hook", fn, "hook surface")
    if impl is None:
        return 1
    return int(impl(repo=args.repo))


def cmd_demo_log(_args: argparse.Namespace) -> int:
    # Generates a realistic audit log so the TUI/landing/demo render against real-
    # shaped data without needing the live proxy. Owner: worker-opus-1 (audit_demo).
    gen = _lane("audit_demo", "main", "worker-opus-1")
    if gen is None:
        return 1
    return int(gen() or 0)


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"tripwire {__version__}")
    return 0


# ---------------------------------------------------------------------------
# parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tripwire",
        description="Local-first leak firewall — see and redact exactly what your "
                    "AI tools send to the cloud. Nothing leaves the building.",
    )
    p.add_argument("-V", "--version", action="store_true", help="print version and exit")
    p.add_argument("--semantic", action="store_true",
                   help="enable the optional local-model pass (default: rules-only — the "
                        "deterministic path all our claims rest on; semantic can false-positive "
                        "on placeholder keys, so it's opt-in)")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    sp = sub.add_parser("scan", help="scan files for secrets/PII/leaks (offline)")
    sp.add_argument("path", nargs="*", help="file(s) to scan")
    sp.add_argument("--show-redacted", action="store_true",
                    help="print the redacted text after findings")
    sp.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default="medium",
                    help="exit 2 if any finding is at/above this severity (default: medium; lists all regardless)")
    sp.set_defaults(func=cmd_scan)

    rp = sub.add_parser("run", help="run an AI tool behind the egress proxy")
    rp.add_argument("--proxy-url", default="http://127.0.0.1:8747",
                    help="local proxy URL the tool is pointed at (path-prefix routing: /anthropic, /openai)")
    rp.add_argument("--no-proxy", action="store_true",
                    help="don't auto-start the proxy (assume one is already running)")
    rp.add_argument("--mode", choices=["monitor", "redact", "block"], default="redact",
                    help="monitor=log only · redact=mask secrets before forwarding · block=refuse (default)")
    rp.add_argument("cmd", nargs=argparse.REMAINDER,
                    help="-- <tool> [args...] (everything after -- is the child command)")
    rp.set_defaults(func=cmd_run)

    pp = sub.add_parser("proxy", help="start the egress proxy standalone")
    pp.add_argument("--host", default="127.0.0.1")
    pp.add_argument("--port", type=int, default=8747)
    pp.add_argument("--mode", choices=["monitor", "redact", "block"], default="redact",
                    help="monitor=log only · redact=mask secrets before forwarding · block=refuse (default)")
    pp.set_defaults(func=cmd_proxy)

    wp = sub.add_parser("watch", help="live TUI of intercepted egress (the dashboard)")
    wp.add_argument("--audit-path", default=None, help="audit log to tail")
    wp.set_defaults(func=cmd_watch)

    hp = sub.add_parser("install-hook", help="install the git pre-commit leak gate")
    hp.add_argument("--repo", default=".", help="repo to install into")
    hp.add_argument("--uninstall", action="store_true", help="remove the hook instead")
    hp.set_defaults(func=cmd_install_hook)

    dp = sub.add_parser("demo-log", help="generate a realistic sample audit log (for the dashboard/demo)")
    dp.set_defaults(func=cmd_demo_log)

    vp = sub.add_parser("version", help="print version")
    vp.set_defaults(func=cmd_version)

    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    args = parser.parse_args(argv)
    # Rules-only by default; --semantic opts into the local-model pass. Set the env
    # the scanner reads BEFORE any lane imports/scans, so scan/run/proxy all inherit
    # it (the proxy starts in-process, so it inherits too). Hook is invoked by git
    # outside this process — scanner's own default must also be off (flagged to scanner owner).
    os.environ["TRIPWIRE_SEMANTIC"] = "1" if getattr(args, "semantic", False) else "0"
    if getattr(args, "version", False):
        return cmd_version(args)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return int(args.func(args))
