"""End-to-end integration smoke. Owner: worker-opus-5.

Proves the REAL pipeline — actual proxy + actual scanner + actual audit, with NO
stubs injected — stops a live secret before it reaches the wire and records it.
This is the "does the whole product actually work" gate behind the Show HN demo.

Assembled from the canonical package-per-lane lanes exactly as worker-opus-2's
integration plan (#407) sequences master: proxy/ + scanner/ + audit + adapters.

Hermetic: TRIPWIRE_SEMANTIC=0 pins it to the deterministic rules layer so it passes
in CI with no ollama. The rules layer catches every secret planted here.
"""
from __future__ import annotations

import os

import pytest
from aiohttp import ClientSession, web

from tripwire import adapters, audit
from tripwire.proxy import Proxy

# real secret shapes the rules layer flags (NOT the AWS doc-example, which is a decoy)
OPENAI_KEY = "sk-proj-aZ12bY34cX56dW78eV90fU12gT34hS56iR78jQ90kP12lO34"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890\n-----END RSA PRIVATE KEY-----"


@pytest.fixture(autouse=True)
def _deterministic_scanner(monkeypatch):
    monkeypatch.setenv("TRIPWIRE_SEMANTIC", "0")  # rules-only → hermetic, no ollama


class _Echo:
    """Fake upstream that records the body it actually received off the wire."""

    def __init__(self):
        self.last_body = None
        self.runner = None
        self.base = None

    async def start(self):
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self._h)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.base = f"http://127.0.0.1:{list(self.runner.addresses)[0][1]}"
        return self.base

    async def stop(self):
        await self.runner.cleanup()

    async def _h(self, request):
        self.last_body = await request.text()
        return web.json_response({"ok": True})


async def _real_proxy(echo_base, mode, audit_log):
    # NO scanner/redactor/on_event injected → exercises the REAL default wiring:
    # tripwire.scanner.scan/redact + tripwire.audit.record.
    os.environ["LEAKPROOF_AUDIT_LOG"] = str(audit_log)
    p = Proxy(port=0, mode=mode, upstreams={"anthropic": echo_base}, tool="claude-code")
    await p.start()
    return p


@pytest.mark.asyncio
async def test_real_pipeline_redacts_live_secret(tmp_path):
    log = tmp_path / "audit.jsonl"
    echo = _Echo()
    base = await echo.start()
    p = await _real_proxy(base, "redact", log)
    try:
        async with ClientSession() as c:
            body = f'{{"messages":[{{"role":"user","content":"my key is {OPENAI_KEY}"}}]}}'
            r = await c.post(f"{p.base_url}/anthropic/v1/messages", data=body)
            assert r.status == 200

        # the secret NEVER reached the upstream — the whole point of the product
        assert OPENAI_KEY not in echo.last_body
        assert "redacted" in echo.last_body

        # the REAL audit log recorded the catch with a redacted-only preview
        events = audit.read_events(log)
        assert len(events) == 1
        e = events[0]
        assert e.action == "redacted"
        assert e.source == "proxy"
        assert e.tool == "claude-code"
        assert any(f.type == "openai_key" for f in e.findings)
        assert e.bytes_redacted > 0
        assert OPENAI_KEY not in e.preview
    finally:
        await p.stop()
        await echo.stop()


@pytest.mark.asyncio
async def test_real_pipeline_blocks_private_key_before_wire(tmp_path):
    log = tmp_path / "audit.jsonl"
    echo = _Echo()
    base = await echo.start()
    p = await _real_proxy(base, "block", log)
    try:
        async with ClientSession() as c:
            body = f'{{"deploy_key":"{PRIVATE_KEY}"}}'
            r = await c.post(f"{p.base_url}/anthropic/v1/messages", data=body)
            assert r.status == 403

        assert echo.last_body is None  # blocked — never touched the upstream
        events = audit.read_events(log)
        assert events[0].action == "blocked"
        assert any(f.type == "private_key" for f in events[0].findings)
    finally:
        await p.stop()
        await echo.stop()


@pytest.mark.asyncio
async def test_clean_request_reaches_upstream_unchanged(tmp_path):
    log = tmp_path / "audit.jsonl"
    echo = _Echo()
    base = await echo.start()
    p = await _real_proxy(base, "redact", log)
    try:
        async with ClientSession() as c:
            body = '{"messages":[{"role":"user","content":"refactor this function please"}]}'
            r = await c.post(f"{p.base_url}/anthropic/v1/messages", data=body)
            assert r.status == 200
        assert echo.last_body == body  # nothing flagged → byte-identical passthrough
        assert audit.read_events(log)[0].action == "passed"
    finally:
        await p.stop()
        await echo.stop()


def test_adapters_env_points_tools_at_the_proxy():
    """No network: the `run -- <tool>` env wiring matches the proxy's path-prefix routing
    (incl. opus-1-2's #411 OpenAI /v1 fix). Closes the loop the live demo depends on."""
    claude = adapters.build_env("claude", "http://127.0.0.1:8747", {})
    assert claude["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:8747/anthropic"

    aider = adapters.build_env("aider", "http://127.0.0.1:8747", {})
    assert aider["OPENAI_API_BASE"] == "http://127.0.0.1:8747/openai/v1"
