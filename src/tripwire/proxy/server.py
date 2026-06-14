"""L1 — egress intercept proxy.  Owner: worker-opus-5.

A local HTTP reverse-proxy that AI coding tools point at via base-URL env
(ANTHROPIC_BASE_URL / OPENAI_API_BASE).  It scans each OUTBOUND request body for
secrets/PII, redacts or blocks per mode, forwards the (possibly redacted) request
to the real upstream, and streams the response straight back untouched.  Every
intercepted request emits an audit event so the TUI can show exactly what your
editor tried to send to the cloud.

Locked contracts (intercom):
  scanner (worker-2 #370):  scan(text, ctx=None) -> [Finding] ; redact(text, findings) -> text'
  audit   (opus-4  #371):   record(event) ; event shape below, JSONL @ ~/.local/share/airlock/audit.jsonl

The Proxy takes scanner/redactor/on_event as injected callables (defaulting to the
sibling lanes' modules) so this file compiles + tests fully standalone before
scanner.py / audit.py exist.
"""
from __future__ import annotations

import asyncio
import threading
import time
import uuid
from typing import Callable, Optional

from aiohttp import ClientSession, ClientTimeout, web

# Path-prefix → real upstream.  One proxy fronts every tool; adapters point each
# tool at  http://127.0.0.1:8747/<key>  and we map <key> to the real API host.
UPSTREAMS: dict[str, str] = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com",
}

# Hop-by-hop headers must not be forwarded (RFC 7230 §6.1) + ones aiohttp sets itself.
_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
    "content-encoding",  # upstream re-encodes; let aiohttp handle length/encoding
}

_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

Finding = dict
Scanner = Callable[[str, Optional[dict]], list]
Redactor = Callable[[str, list], str]
EventSink = Callable[[dict], None]
DEFAULT_PORT = 8747  # "TRIP" — avoids primer-mock on :8799 on this box


# ── default lane bindings (best-effort; proxy works even if they're absent) ──
# Relative imports first → name-agnostic, so the tripwire→leakproof rename is free.
# Absolute + bare fallbacks keep this module importable standalone (tests inject stubs).
def _default_scanner(text: str, ctx: Optional[dict] = None) -> list:
    try:
        from ..scanner import scan  # type: ignore
    except Exception:
        try:
            from scanner import scan  # type: ignore
        except Exception:
            return []
    return scan(text, ctx)


def _default_redactor(text: str, findings: list) -> str:
    try:
        from ..scanner import redact  # type: ignore
    except Exception:
        try:
            from scanner import redact  # type: ignore
        except Exception:
            return text
    return redact(text, findings)


def _default_sink(event: dict) -> None:
    try:
        from .. import audit  # type: ignore
    except Exception:
        try:
            import audit  # type: ignore
        except Exception:
            return
    audit.record(event)


class Proxy:
    """Async egress-intercept reverse proxy. Start/stop programmatically (cli.py
    owns lifecycle) or via `serve()` for a standalone smoke test."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = DEFAULT_PORT,
        *,
        mode: str = "redact",  # "monitor" | "redact" | "block"
        scanner: Scanner = _default_scanner,
        redactor: Redactor = _default_redactor,
        on_event: EventSink = _default_sink,
        block_severity: str = "high",  # in block mode, reject findings >= this
        upstreams: Optional[dict] = None,
        tool: Optional[str] = None,
        max_body: int = 64 * 1024 * 1024,
    ) -> None:
        self.host = host
        self.port = port
        self.mode = mode
        self.scan = scanner
        self.redact = redactor
        self.emit = on_event
        self.block_severity = block_severity
        self.upstreams = dict(upstreams) if upstreams else dict(UPSTREAMS)
        self.tool = tool
        self.max_body = max_body
        self._runner: Optional[web.AppRunner] = None
        self._session: Optional[ClientSession] = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    async def start(self) -> str:
        # total=None: never time out a long streaming generation; only cap connect.
        self._session = ClientSession(timeout=ClientTimeout(total=None, sock_connect=20))
        app = web.Application(client_max_size=self.max_body)
        app.router.add_route("*", "/{path:.*}", self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        if self.port == 0:  # ephemeral bind → resolve the real port so base_url is correct
            addrs = list(self._runner.addresses)
            if addrs:
                self.port = addrs[0][1]
        return self.base_url

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
        if self._session is not None:
            await self._session.close()
            self._session = None

    # ── routing ──
    def _resolve_upstream(self, path: str):
        """/anthropic/v1/messages -> ("anthropic", "https://api.anthropic.com", "/v1/messages")."""
        parts = path.lstrip("/").split("/", 1)
        key = parts[0]
        rest = "/" + (parts[1] if len(parts) > 1 else "")
        base = self.upstreams.get(key)
        return key, base, rest

    # ── core ──
    async def _handle(self, request: web.Request) -> web.StreamResponse:
        key, base, rest = self._resolve_upstream(request.rel_url.path)
        if base is None:
            return web.json_response(
                {"error": f"airlock: no upstream mapped for '{request.rel_url.path}'. "
                          f"known: {sorted(self.upstreams)}"},
                status=502,
            )

        raw = await request.read()
        body_text = raw.decode("utf-8", "replace") if raw else ""
        findings = self.scan(body_text, {"tool": self.tool, "host": key}) if body_text else []

        action = "passed"
        out_bytes = raw

        threshold = _SEV_RANK.get(self.block_severity, 2)
        hot = [f for f in findings if _SEV_RANK.get(f.get("severity"), 0) >= threshold]

        if findings and self.mode == "block" and hot:
            action = "blocked"
        elif findings and self.mode in ("redact", "block"):
            redacted = self.redact(body_text, findings)
            if redacted != body_text:
                out_bytes = redacted.encode("utf-8")
                action = "redacted"
        # mode == "monitor": always forward unchanged, action stays "passed"

        self._safe_emit(self._event(request, key, base, raw, findings, action, body_text))

        if action == "blocked":
            return web.json_response(
                {
                    "error": {
                        "type": "airlock_blocked",
                        "message": f"airlock blocked this request — {len(hot)} secret(s) "
                                   f"would have left your machine. Run with --mode redact to "
                                   f"strip them instead, or --mode monitor to allow.",
                        "findings": [
                            {"type": f.get("type"), "severity": f.get("severity"),
                             "reason": f.get("reason")}
                            for f in hot
                        ],
                    }
                },
                status=403,
            )

        return await self._forward(request, base, rest, out_bytes)

    async def _forward(self, request, base, rest, body) -> web.StreamResponse:
        assert self._session is not None
        url = base + rest
        if request.query_string:
            url += "?" + request.query_string
        fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP}
        try:
            upstream = await self._session.request(
                request.method,
                url,
                headers=fwd_headers,
                data=body if body else None,
                allow_redirects=False,
            )
        except Exception as e:  # upstream unreachable / TLS / dns
            return web.json_response({"error": f"airlock upstream error: {e}"}, status=502)

        resp = web.StreamResponse(
            status=upstream.status,
            headers={k: v for k, v in upstream.headers.items() if k.lower() not in _HOP},
        )
        await resp.prepare(request)
        try:
            async for chunk in upstream.content.iter_any():  # SSE-safe streaming passthrough
                await resp.write(chunk)
            await resp.write_eof()
        finally:
            upstream.release()
        return resp

    # ── audit ──
    def _event(self, request, key, base, raw, findings, action, body_text) -> dict:
        # preview is always already-redacted — a DLP tool must never persist raw secrets.
        preview = ""
        if body_text:
            shown = self.redact(body_text, findings) if findings else body_text
            preview = shown[:300]
        # bytes_redacted powers the "N KB stopped from leaving" headline (audit.aggregate):
        #   blocked → the whole payload was stopped; redacted → just the secret spans.
        if action == "blocked":
            bytes_redacted = len(raw)
        elif action == "redacted":
            bytes_redacted = sum(
                max(0, f["span"][1] - f["span"][0]) for f in findings if "span" in f
            )
        else:
            bytes_redacted = 0
        return {
            "id": uuid.uuid4().hex,
            "ts": time.time(),
            "source": "proxy",
            "tool": self.tool,
            "method": request.method,
            "host": key,
            "url": base + request.rel_url.path,
            "target": None,
            "action": action,
            "findings": findings,
            "n_findings": len(findings),
            "bytes_in": len(raw),
            "bytes_redacted": bytes_redacted,
            "preview": preview,
        }

    def _safe_emit(self, event: dict) -> None:
        try:
            self.emit(event)
        except Exception:
            pass  # audit is best-effort; never fail a request over a log write


async def run_proxy(**kw) -> Proxy:
    """Start a proxy and return it (caller awaits .stop()). Async callers."""
    p = Proxy(**kw)
    await p.start()
    return p


class BackgroundProxy:
    """Run a Proxy on its own event loop in a daemon thread, for SYNC callers.

    This is the seam cli.py's `run -- <tool>` uses: start the proxy, hand its
    base_url to adapters.run(), then stop it when the child exits — all without
    the cli needing to be async.
    """

    def __init__(self, **kw) -> None:
        self._kw = kw
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True, name="leakproof-proxy")
        self._proxy: Optional[Proxy] = None
        self._ready = threading.Event()
        self._err: Optional[BaseException] = None
        self.base_url: Optional[str] = None

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        try:
            self._proxy = Proxy(**self._kw)
            self.base_url = self._loop.run_until_complete(self._proxy.start())
        except BaseException as e:  # surface bind errors to the caller
            self._err = e
            self._ready.set()
            return
        self._ready.set()
        self._loop.run_forever()

    def start(self, timeout: float = 15.0) -> str:
        self._thread.start()
        if not self._ready.wait(timeout=timeout):
            raise TimeoutError("proxy failed to start")
        if self._err is not None:
            raise self._err
        assert self.base_url is not None
        return self.base_url

    def stop(self) -> None:
        if self._proxy is not None:
            fut = asyncio.run_coroutine_threadsafe(self._proxy.stop(), self._loop)
            try:
                fut.result(timeout=10)
            except Exception:
                pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)


def start_background(host: str = "127.0.0.1", port: int = DEFAULT_PORT, *,
                     mode: str = "redact", **kw) -> BackgroundProxy:
    """Sync helper: start a proxy in the background and return it (call .stop() when done)."""
    bp = BackgroundProxy(host=host, port=port, mode=mode, **kw)
    bp.start()
    return bp


def serve(host: str = "127.0.0.1", port: int = DEFAULT_PORT, *, mode: str = "redact", **kw) -> int:
    """Blocking standalone proxy — matches cli's `proxy.serve(host, port) -> int`.
    Runs until Ctrl-C; returns a process exit code."""
    async def _main():
        p = Proxy(host=host, port=port, mode=mode, **kw)
        url = await p.start()
        print(f"leakproof proxy on {url}  mode={p.mode}  upstreams={sorted(p.upstreams)}")
        print(f"point your AI tool at it, e.g.  ANTHROPIC_BASE_URL={url}/anthropic")
        try:
            await asyncio.Event().wait()
        finally:
            await p.stop()

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        print("\nleakproof proxy stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
