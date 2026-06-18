"""Deterministic secret/PII detectors — the regex + entropy fast-path.

Zero dependencies (stdlib only) so the core scans with no model and no network.
Each detector yields findings in the locked scanner contract shape:

    {"type", "span":[start,end], "severity", "reason", "redaction", "source":"rules"}

Design notes:
  * Patterns are tuned to catch *real* credentials while a placeholder/example
    filter (`_is_placeholder`) suppresses the obvious fakes (AWS docs keys,
    `your_api_key_here`, `xxxx...`) so we don't drown a security tool in false
    positives — false-positive noise is how scanners get uninstalled.
  * High-entropy detection is deliberately conservative: a long token only fires
    if its Shannon entropy clears a threshold AND it isn't a placeholder, so prose
    and hex hashes-of-public-things don't light up.
"""

from __future__ import annotations

import math
import re
from typing import Iterable

# --- severity helpers ---------------------------------------------------------------

SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _finding(type_: str, start: int, end: int, severity: str, reason: str) -> dict:
    return {
        "type": type_,
        "span": [start, end],
        "severity": severity,
        "reason": reason,
        "redaction": f"‹{type_} redacted›",  # ‹type redacted›
        "source": "rules",
    }


# --- placeholder / example suppression ----------------------------------------------

# Known documentation/example values + obvious placeholders. A literal-substring or
# regex hit here means "not a real secret" → suppress.
_PLACEHOLDER_LITERALS = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "0123456789abcdef",
    "deadbeef",
}

_PLACEHOLDER_RE = re.compile(
    r"""(?ix)
    ^(?:
        (?:x{4,})                       # xxxx...
      | (?:0{4,})                       # 0000...
      | (?:\.{3,})                      # ...
      | (?:<[^>]*>)                     # <your-key-here>
      | (?:\$\{[^}]*\})                 # ${ENV_VAR}
      | (?:your[_-]?\w+)                # your_api_key
      | (?:my[_-]?\w+)                  # my_secret
      | (?:(?:example|sample|dummy|placeholder|changeme|redacted|test|fake|todo)[\w-]*)
      | (?:[\w-]*(?:example|placeholder|changeme|xxxx)[\w-]*)
    )$
    """
)


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"")
    if v in _PLACEHOLDER_LITERALS:
        return True
    if "EXAMPLE" in v or "example" in v and "@example" not in v:
        # 'EXAMPLE' embedded in an otherwise key-shaped string ⇒ doc sample.
        if re.search(r"example", v, re.I):
            return True
    return bool(_PLACEHOLDER_RE.match(v))


# --- entropy ------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Bits per character. ~0 for repetitive strings, ~4-6 for random base64/hex."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --- pattern table ------------------------------------------------------------------
# (type, severity, compiled-regex, capture-group-for-the-secret, reason)
# group 0 = whole match is the secret; a positive int = that capture group.

_PATTERNS: list[tuple[str, str, re.Pattern, int, str]] = [
    ("aws_access_key_id", "high",
     re.compile(r"\b(?:AKIA|ASIA|AGPA|AROA|AIDA)[0-9A-Z]{16}\b"), 0,
     "AWS access key ID"),
    ("github_token", "critical",
     re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"), 0,
     "GitHub access token"),
    ("github_pat", "critical",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), 0,
     "GitHub fine-grained personal access token"),
    ("anthropic_key", "critical",
     re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), 0,
     "Anthropic API key"),
    ("openai_key", "critical",
     re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}\b"), 0,
     "OpenAI API key"),
    ("stripe_secret_key", "critical",
     re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"), 0,
     "Stripe live secret key"),
    ("slack_token", "high",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0,
     "Slack token"),
    ("google_api_key", "high",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), 0,
     "Google API key"),
    ("jwt", "medium",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0,
     "JSON Web Token (may carry claims/credentials)"),
    ("private_key", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
                r"[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"), 0,
     "PEM private key block"),
    ("db_url_with_credentials", "high",
     re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
                r"[^\s:/@]+:[^\s:/@]+@[^\s/]+"), 0,
     "Database URL with embedded username:password"),
    ("gitlab_token", "critical",
     re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), 0,
     "GitLab personal access token"),
    ("npm_token", "critical",
     re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), 0,
     "npm access token"),
    ("pypi_token", "critical",
     re.compile(r"\bpypi-AgE[A-Za-z0-9_-]{50,}\b"), 0,
     "PyPI API token"),
    ("sendgrid_key", "critical",
     re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), 0,
     "SendGrid API key"),
    ("huggingface_token", "high",
     re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"), 0,
     "Hugging Face access token"),
    ("twilio_api_key", "high",
     re.compile(r"\bSK[0-9a-f]{32}\b"), 0,
     "Twilio API key SID"),
    ("digitalocean_token", "critical",
     re.compile(r"\b(?:dop|doo|dor)_v1_[a-f0-9]{64}\b"), 0,
     "DigitalOcean API token"),
    ("square_token", "critical",
     re.compile(r"\b(?:sq0atp|sq0csp)-[A-Za-z0-9_-]{22,}\b"), 0,
     "Square access token"),
    ("shopify_token", "critical",
     re.compile(r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b"), 0,
     "Shopify access token"),
    ("postman_key", "high",
     re.compile(r"\bPMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34}\b"), 0,
     "Postman API key"),
    ("linear_key", "high",
     re.compile(r"\blin_api_[A-Za-z0-9]{40,}\b"), 0,
     "Linear API key"),
    ("mailgun_key", "high",
     re.compile(r"\bkey-[a-f0-9]{32}\b"), 0,
     "Mailgun API key"),
    ("telegram_bot_token", "high",
     re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"), 0,
     "Telegram bot token"),
    ("azure_storage_key", "high",
     re.compile(r"AccountKey=[A-Za-z0-9+/]{86}=="), 0,
     "Azure Storage account key"),
    ("pii_email", "low",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0,
     "Email address (PII)"),
]

# Generic `key = "value"` assignment: catches secrets that don't match a vendor shape.
_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b(api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|
       password|passwd|client[_-]?secret|private[_-]?key)\b
    \s*[:=]\s*
    (['"]?)
    (?P<val>[^\s'"]{8,})
    \2
    """
)

# Tokens worth an entropy check: long base64/hex-ish runs. `=` is allowed only as
# trailing base64 padding — NOT as a mid-token char, else an assignment like
# `NAME=sk_test_...` merges the LHS in and defeats prefix-based suppression.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_\-]{20,}={0,2}")
_ENTROPY_MIN = 3.6          # bits/char; random base64 ~6, hex ~4
_ENTROPY_MIN_LEN = 24


# --- benign high-entropy shapes (suppress so we don't false-positive) ---------------

# Vendor "test mode" keys are not live credentials → at most informational, never block.
_TEST_KEY_RE = re.compile(r"\b(?:sk|rk|pk)_test_[A-Za-z0-9]{10,}\b")

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HASH_LENGTHS = {32, 40, 64}  # md5 / sha1 / git-sha / sha256 — high entropy, not secrets


def _is_test_key(token: str) -> bool:
    return bool(_TEST_KEY_RE.fullmatch(token)) or token.startswith(("sk_test_", "rk_test_", "pk_test_"))


def _looks_like_hash(token: str) -> bool:
    """Pure-hex of a common digest length ⇒ almost certainly a hash/SHA, not a secret."""
    return len(token) in _HASH_LENGTHS and bool(_HEX_RE.match(token))


# --- credit card (Luhn) -------------------------------------------------------------

# Famous vendor TEST PANs — must never be reported as a cardholder leak.
_KNOWN_TEST_PANS = {
    "4242424242424242", "4111111111111111", "4012888888881881",
    "5555555555554444", "5105105105105100", "2223003122003222",
    "378282246310005", "371449635398431", "6011111111111117",
    "30569309025904", "3530111333300000",
}
_PAN_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# --- phone (PII) --------------------------------------------------------------------

_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[ .\-]?)?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}(?!\d)"
)


# --- bulk source paste (volume heuristic) -------------------------------------------

_CODE_LINE_RE = re.compile(
    r"^\s*(?:def |class |import |from |return |if |for |while |@|\}|\{|.*;\s*$|.*=.*)"
)
_BULK_MIN_CODE_LINES = 25  # a whole-file paste, not an incidental snippet


# --- example-email suppression ------------------------------------------------------

_EXAMPLE_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "test.com")


def _email_is_example(match_text: str) -> bool:
    return any(match_text.lower().endswith("@" + d) or match_text.lower().endswith("." + d)
               for d in _EXAMPLE_EMAIL_DOMAINS)


# --- main entry ---------------------------------------------------------------------

def scan_rules(text: str) -> list[dict]:
    """Run every deterministic detector over `text`. Returns un-deduped findings."""
    out: list[dict] = []

    for type_, severity, pat, grp, reason in _PATTERNS:
        for m in pat.finditer(text):
            secret = m.group(grp)
            start, end = m.span(grp)
            if type_ == "pii_email" and _email_is_example(secret):
                continue
            if _is_placeholder(secret):
                continue
            out.append(_finding(type_, start, end, severity, reason))

    # Generic assignment secrets (value group only).
    for m in _ASSIGNMENT_RE.finditer(text):
        val = m.group("val")
        if _is_placeholder(val):
            continue
        start, end = m.span("val")
        key_name = m.group(1).lower()
        out.append(_finding(
            "generic_secret_assignment", start, end, "high",
            f"Hardcoded secret assigned to '{key_name}'",
        ))

    # Vendor TEST keys: report as informational (never blocks) and suppress the entropy
    # detector from re-flagging them as a medium "secret".
    test_key_spans: list[tuple[int, int]] = []
    for m in _TEST_KEY_RE.finditer(text):
        test_key_spans.append(m.span())
        out.append(_finding(
            "vendor_test_key", m.start(), m.end(), "low",
            "Vendor test-mode key (sk_test_/pk_test_) — not a live credential",
        ))

    # Credit-card PANs (Luhn-valid), excluding well-known vendor test cards.
    for m in _PAN_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if not _luhn_valid(digits) or digits in _KNOWN_TEST_PANS:
            continue
        out.append(_finding(
            "credit_card", m.start(), m.end(), "high",
            "Luhn-valid credit-card number (PCI / PII)",
        ))

    # Phone numbers (PII).
    for m in _PHONE_RE.finditer(text):
        # don't mistake a slice of a long digit run (e.g. a PAN) for a phone number
        digits = re.sub(r"\D", "", m.group(0))
        if not (7 <= len(digits) <= 13):
            continue
        out.append(_finding(
            "pii_phone", m.start(), m.end(), "medium",
            "Phone number (PII)",
        ))

    # Entropy fallback for high-entropy tokens not already covered.
    for m in _TOKEN_RE.finditer(text):
        tok = m.group(0)
        if len(tok) < _ENTROPY_MIN_LEN:
            continue
        if _is_placeholder(tok) or _is_test_key(tok) or _looks_like_hash(tok):
            continue
        if any(s <= m.start() and m.end() <= e for s, e in test_key_spans):
            continue
        if shannon_entropy(tok) >= _ENTROPY_MIN:
            out.append(_finding(
                "high_entropy_string", m.start(), m.end(), "medium",
                f"High-entropy string (entropy={shannon_entropy(tok):.1f} bits/char) "
                f"— possible credential",
            ))

    # Bulk source-code paste (whole-file exfil) — volume heuristic, no single token.
    bulk = _detect_bulk_paste(text)
    if bulk is not None:
        out.append(bulk)

    return out


def _detect_bulk_paste(text: str) -> dict | None:
    """Flag a large block of source code (a whole-file paste) — exfil by volume.

    Conservative: needs many code-shaped lines so an incidental snippet won't trip it.
    """
    lines = text.splitlines()
    code_lines = sum(1 for ln in lines if ln.strip() and _CODE_LINE_RE.match(ln))
    if code_lines >= _BULK_MIN_CODE_LINES:
        # Zero-width, document-level marker: it must NOT overlap/suppress real token
        # findings in the same body, and redact() leaves the body intact (block-mode's job).
        return _finding(
            "bulk_source_paste", 0, 0, "medium",
            f"Bulk source-code paste ({code_lines} code lines) — possible whole-file exfiltration",
        )
    return None


def iter_secret_types() -> Iterable[str]:
    """The vendor secret types this fast-path knows (for docs/tests)."""
    return (t for t, *_ in _PATTERNS)
