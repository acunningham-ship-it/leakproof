"""Optional local-model semantic pass — the differentiator over regex scanners.

Regex catches *shaped* secrets (AKIA…, ghp_…). It misses the leaks that have no
fixed shape: a real production DB hostname, a live customer email sitting in a test
fixture, an internal-only URL, a credential whose vendor we don't have a pattern for,
a secret described in prose. A small LOCAL model reads the chunk and flags those.

Key properties:
  * LOCAL by construction — runs on ollama (default `qwen2.5:1.5b`, verified live on
    this box) or any OpenAI-/ollama-compatible endpoint. The whole point of the product
    is that the scanner never ships your text to a cloud, so this layer must stay local.
  * BEST-EFFORT — if the model is unreachable, slow, or returns junk, scan() degrades
    cleanly to the regex fast-path. A security tool must never fail-open silently *or*
    crash the commit; here a model miss just means "rules-only this run".
  * DETERMINISTIC TESTS — the network call is injected (`call_model`), so tests pin a
    canned model response and assert mapping without needing ollama up.

Output is mapped into the same locked Finding shape, with source="semantic".
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Callable

# Bound what we send to the model so a giant blob can't hang the commit/proxy.
_MAX_CHARS = 8000
_TIMEOUT_S = float(os.environ.get("LEAKPROOF_SEMANTIC_TIMEOUT", "12"))

_PROMPT = """\
You are a secret/PII leak detector. You are given a chunk of text from a developer's \
code diff or an outbound request body. Find anything that should NOT leave the machine: \
credentials, API keys/tokens, passwords, private keys, real production hostnames/URLs, \
database connection strings, or personal data (real names+emails, phone numbers, \
customer records). IGNORE obvious placeholders, example/dummy values, and public \
constants.

Return ONLY a JSON array (no prose). Each element:
  {"snippet": "<the exact leaking VALUE, copied verbatim from the text — the secret/\
hostname/email itself, NOT a label or variable name>", "type": "<short_snake_case_label>", \
"severity": "critical|high|medium|low", "reason": "<why this is a leak>"}
The snippet MUST be an exact substring of the text (so it can be located and redacted).
If nothing is found, return [].

TEXT:
<<<
%s
>>>
"""

# Vendor-shaped types the regex fast-path already owns — drop semantic dupes of these
# so we don't double-report the same AKIA… key from both layers.
_RULES_OWNED = {
    "aws_access_key_id", "github_token", "github_pat", "anthropic_key", "openai_key",
    "stripe_secret_key", "slack_token", "google_api_key", "jwt", "private_key",
}

_VALID_SEVERITY = {"critical", "high", "medium", "low"}


def _ollama_call(prompt: str) -> str:
    """Default model transport: ollama /api/generate. Returns raw completion text."""
    base = os.environ.get("LEAKPROOF_OLLAMA_URL", "http://localhost:11434").rstrip("/")
    model = os.environ.get("LEAKPROOF_SEMANTIC_MODEL", "qwen2.5:1.5b")
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0},
        "format": "json",
    }).encode()
    req = urllib.request.Request(
        base + "/api/generate", data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
        body = json.loads(resp.read().decode())
    return body.get("response", "")


def semantic_enabled() -> bool:
    """Off only if explicitly disabled. Default on (best-effort)."""
    return os.environ.get("LEAKPROOF_SEMANTIC", "0").strip().lower() not in ("0", "false", "no")


def _parse_model_json(raw: str) -> list[dict]:
    """Pull a JSON array out of the model's reply, tolerantly."""
    raw = raw.strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Model wrapped it in prose/markdown — grab the first [...] block.
        start, end = raw.find("["), raw.rfind("]")
        if start == -1 or end == -1 or end < start:
            return []
        try:
            data = json.loads(raw[start:end + 1])
        except json.JSONDecodeError:
            return []
    if isinstance(data, dict):
        # Small models often return a single finding OBJECT or wrap the list under a key.
        for key in ("findings", "results", "leaks", "items"):
            if isinstance(data.get(key), list):
                return data[key]
        if "snippet" in data or "type" in data:  # a lone finding object
            return [data]
        return []
    return data if isinstance(data, list) else []


def scan_semantic(
    text: str,
    call_model: Callable[[str], str] | None = None,
) -> list[dict]:
    """Best-effort semantic leak detection. Returns findings or [] on any failure.

    `call_model` is injectable for tests; defaults to the local ollama transport.
    """
    if not text.strip() or not semantic_enabled():
        return []

    transport = call_model or _ollama_call
    chunk = text[:_MAX_CHARS]
    try:
        raw = transport(_PROMPT % chunk)
    except (urllib.error.URLError, OSError, TimeoutError):
        return []  # model down ⇒ degrade to rules-only, never crash
    except Exception:
        return []

    findings: list[dict] = []
    for item in _parse_model_json(raw):
        if not isinstance(item, dict):
            continue
        snippet = str(item.get("snippet", "")).strip()
        if not snippet:
            continue
        type_ = str(item.get("type", "semantic_leak")).strip() or "semantic_leak"
        if type_ in _RULES_OWNED:
            continue  # let the deterministic layer own vendor-shaped hits
        severity = str(item.get("severity", "medium")).strip().lower()
        if severity not in _VALID_SEVERITY:
            severity = "medium"
        reason = str(item.get("reason", "model-flagged potential leak")).strip()

        # Locate the snippet in the original text to produce a real span. If the model
        # paraphrased and we can't find it, skip (we won't redact text we can't locate).
        idx = text.find(snippet)
        if idx == -1:
            continue
        findings.append({
            "type": type_,
            "span": [idx, idx + len(snippet)],
            "severity": severity,
            "reason": reason,
            "redaction": f"‹{type_} redacted›",
            "source": "semantic",
        })
    return findings
