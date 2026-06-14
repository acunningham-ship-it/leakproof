"""L1 proxy unit tests. Owner: worker-opus-5.

Spins up a real fake-upstream aiohttp server, points the proxy at it via an injected
upstream map, and drives requests through with a real client. Stub scanner flags the
literal "SECRET123" so we can assert the upstream received the REDACTED body, that
block mode 403s, that monitor passes raw, and that a chunked/SSE response streams
back intact.
"""
from __future__ import annotations

import asyncio
import json

import pytest
from aiohttp import ClientSession, web

from leakproof.proxy import Proxy, start_background

SECRET = "SECRET123"
REDACTION = "‹redacted›"


# ── stub lanes (stand in for worker-2's scanner) ──
def stub_scan(text, ctx=None):
    out = []
    start = text.find(SECRET)
    while start != -1:
        out.append({
            "type": "test_secret",
            "span": [start, start + len(SECRET)],
            "severity": "high",
            "reason": "planted test secret",
            "redaction": REDACTION,
            "source": "rules",
        })
        start = text.find(SECRET, start + len(SECRET))
    return out


def stub_redact(text, findings):
    for f in sorted(findings, key=lambda f: f["span"][0], reverse=True):
        s, e = f["span"]
        text = text[:s] + f["redaction"] + text[e:]
    return text


# ── a fake upstream that echoes what it received (so we can inspect the outbound body) ──
class FakeUpstream:
    def __init__(self):
        self.last_body = None
        self.last_headers = None
        self.runner = None
        self.port = None

    async def start(self):
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self._echo)
        app.router.add_get("/sse", self._sse)  # overridden below by route order? use distinct
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = list(self.runner.addresses)[0][1]
        return f"http://127.0.0.1:{self.port}"

    async def stop(self):
        await self.runner.cleanup()

    async def _echo(self, request):
        self.last_body = await request.text()
        self.last_headers = dict(request.headers)
        if request.rel_url.path.endswith("/sse"):
            return await self._sse(request)
        return web.json_response({"echo": self.last_body, "ok": True})

    async def _sse(self, request):
        resp = web.StreamResponse(
            status=200, headers={"Content-Type": "text/event-stream"}
        )
        await resp.prepare(request)
        for i in range(5):
            await resp.write(f"data: chunk{i}\n\n".encode())
            await asyncio.sleep(0)
        await resp.write(b"data: [DONE]\n\n")
        await resp.write_eof()
        return resp


async def _make(mode="redact", **kw):
    up = FakeUpstream()
    base = await up.start()
    p = Proxy(
        port=0,  # ephemeral
        mode=mode,
        scanner=stub_scan,
        redactor=stub_redact,
        on_event=kw.pop("on_event", lambda e: None),
        upstreams={"test": base},
        tool="pytest",
        **kw,
    )
    await p.start()  # ephemeral port auto-resolves inside start()
    return p, up


@pytest.mark.asyncio
async def test_redacts_outbound_body():
    events = []
    p, up = await _make(mode="redact", on_event=events.append)
    try:
        async with ClientSession() as c:
            r = await c.post(f"{p.base_url}/test/v1/messages",
                             data=f'{{"prompt":"my key is {SECRET} ok"}}')
            body = await r.json()
        # upstream must NOT have seen the secret
        assert SECRET not in up.last_body
        assert REDACTION in up.last_body
        # response still flows back
        assert body["ok"] is True
        # audit event records the catch, redacted preview only
        assert len(events) == 1
        assert events[0]["action"] == "redacted"
        assert events[0]["n_findings"] == 1
        assert SECRET not in events[0]["preview"]
        assert events[0]["source"] == "proxy"
        assert events[0]["host"] == "test"
        assert events[0]["bytes_redacted"] == len(SECRET)  # secret bytes stopped from leaving
    finally:
        await p.stop()
        await up.stop()


@pytest.mark.asyncio
async def test_block_mode_403s_and_does_not_forward():
    events = []
    p, up = await _make(mode="block", on_event=events.append)
    try:
        async with ClientSession() as c:
            r = await c.post(f"{p.base_url}/test/v1/messages",
                             data=f'{{"k":"{SECRET}"}}')
            assert r.status == 403
            payload = await r.json()
        assert payload["error"]["type"] == "airlock_blocked"
        assert up.last_body is None  # never reached upstream
        assert events[0]["action"] == "blocked"
    finally:
        await p.stop()
        await up.stop()


@pytest.mark.asyncio
async def test_monitor_mode_passes_raw_but_logs():
    events = []
    p, up = await _make(mode="monitor", on_event=events.append)
    try:
        async with ClientSession() as c:
            await c.post(f"{p.base_url}/test/v1/messages", data=f'{{"k":"{SECRET}"}}')
        # monitor forwards UNCHANGED (the secret leaves) but still records it
        assert SECRET in up.last_body
        assert events[0]["action"] == "passed"
        assert events[0]["n_findings"] == 1  # still detected + logged
    finally:
        await p.stop()
        await up.stop()


@pytest.mark.asyncio
async def test_clean_request_passes_untouched_no_findings():
    events = []
    p, up = await _make(mode="redact", on_event=events.append)
    try:
        async with ClientSession() as c:
            r = await c.post(f"{p.base_url}/test/v1/messages", data='{"hello":"world"}')
            assert r.status == 200
        assert up.last_body == '{"hello":"world"}'
        assert events[0]["action"] == "passed"
        assert events[0]["n_findings"] == 0
    finally:
        await p.stop()
        await up.stop()


@pytest.mark.asyncio
async def test_sse_streaming_passthrough_intact():
    p, up = await _make(mode="redact")
    try:
        async with ClientSession() as c:
            r = await c.post(f"{p.base_url}/test/sse", data='{"clean":"ok"}')
            text = await r.text()
        # all 5 chunks + DONE survive the proxy intact
        for i in range(5):
            assert f"data: chunk{i}" in text
        assert "[DONE]" in text
    finally:
        await p.stop()
        await up.stop()


@pytest.mark.asyncio
async def test_unknown_upstream_502s():
    p, up = await _make(mode="redact")
    try:
        async with ClientSession() as c:
            r = await c.post(f"{p.base_url}/nope/v1/x", data="{}")
            assert r.status == 502
    finally:
        await p.stop()
        await up.stop()


@pytest.mark.asyncio
async def test_get_with_no_body_forwards():
    p, up = await _make(mode="redact")
    try:
        async with ClientSession() as c:
            r = await c.get(f"{p.base_url}/test/v1/models")
            assert r.status == 200
    finally:
        await p.stop()
        await up.stop()


def test_start_background_serves_sync():
    """The sync seam cli.py's `run -- <tool>` uses: start in a thread, get a live
    base_url, hit it synchronously, stop cleanly. No event loop in the caller."""
    import urllib.error
    import urllib.request

    bp = start_background(
        port=0, mode="redact",
        scanner=stub_scan, redactor=stub_redact, on_event=lambda e: None,
        upstreams={"test": "http://127.0.0.1:1"},  # unroutable → exercises the live listener
    )
    try:
        assert bp.base_url and bp.base_url.startswith("http://127.0.0.1:")
        req = urllib.request.Request(bp.base_url + "/nope/x", method="GET")
        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("expected an HTTP error status")
        except urllib.error.HTTPError as e:
            assert e.code == 502  # unknown upstream → proves the bg thread is serving
    finally:
        bp.stop()
