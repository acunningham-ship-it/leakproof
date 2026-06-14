"""Tests for the scan-core (leakproof.scanner): rules fast-path, semantic pass, redact.

The semantic model call is INJECTED so these run with no ollama/network. A separate
adversarial corpus (worker-3's lane) exercises breadth; this file pins the contract.
"""

import pytest

from leakproof import scanner
from leakproof.scanner import rules, semantic


@pytest.fixture(autouse=True)
def _hermetic_semantic(monkeypatch):
    """Default the semantic layer OFF so rules tests are fast + need no ollama.

    `scan()` is then deterministic (regex/entropy only). Semantic behaviour is covered
    explicitly via injected `call_model` in the tests that opt back in.
    """
    monkeypatch.setenv("LEAKPROOF_SEMANTIC", "0")


@pytest.fixture
def semantic_on(monkeypatch):
    monkeypatch.setenv("LEAKPROOF_SEMANTIC", "1")


# --- real secrets the regex fast-path must catch ------------------------------------

REAL_SECRETS = [
    ("aws_access_key_id", "AKIAZ8R7QWERTYUIOPAS"),
    ("github_token", "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"),
    ("openai_key", "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"),
    ("anthropic_key", "sk-ant-api03-" + "0A1b2C3d4E5f6G7h8I9j0K1L2m3N4o5P6q7R8s9T"),
    ("stripe_secret_key", "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"),
    ("slack_token", "xoxb-123456789012-abcdefABCDEF0123"),
    ("google_api_key", "AIza" + "SyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"),
]


@pytest.mark.parametrize("expected_type,secret", REAL_SECRETS)
def test_real_secret_is_caught(expected_type, secret):
    text = f"const key = '{secret}'  // ship it"
    found = scanner.scan(text)
    types = {f["type"] for f in found}
    assert expected_type in types, f"{expected_type} not in {types}"
    # every finding has the full contract shape
    for f in found:
        assert set(f) >= {"type", "span", "severity", "reason", "redaction", "source"}
        s, e = f["span"]
        assert text[s:e]  # span points at real text


def test_jwt_caught():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
    found = scanner.scan(f"Authorization: Bearer {jwt}")
    assert any(f["type"] == "jwt" for f in found)


def test_private_key_block_caught():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIE" + "abcd" * 20 + "\n"
        "-----END RSA PRIVATE KEY-----"
    )
    found = scanner.scan(pem)
    assert any(f["type"] == "private_key" and f["severity"] == "critical" for f in found)


def test_db_url_with_credentials_caught():
    found = scanner.scan("DATABASE_URL=postgres://admin:s3cr3tP@db.internal.prod:5432/main")
    assert any(f["type"] == "db_url_with_credentials" for f in found)


def test_generic_assignment_secret_caught():
    found = scanner.scan('password = "hunter2hunter2"')
    assert any(f["type"] == "generic_secret_assignment" for f in found)


def test_high_entropy_string_caught():
    blob = "Zx9Q" + "kP7mWvL2nR8tY4uH6jB3cF5dG1sA0eD"  # random-looking, 35 chars
    found = scanner.scan(f"token: {blob}")
    assert any(f["type"] in ("high_entropy_string", "generic_secret_assignment")
               for f in found)


# --- decoys / placeholders the scanner must NOT fire on -----------------------------

DECOYS = [
    "AKIAIOSFODNN7EXAMPLE",                       # AWS docs example key
    "your_api_key_here",
    "xxxxxxxxxxxxxxxxxxxx",
    "<your-token-here>",
    "${OPENAI_API_KEY}",
    "changeme",
]


@pytest.mark.parametrize("decoy", DECOYS)
def test_decoy_not_flagged_as_secret(decoy):
    found = scanner.scan(f"api_key = '{decoy}'")
    # no critical/high secret finding on a placeholder
    bad = [f for f in found if f["severity"] in ("critical", "high")]
    assert not bad, f"placeholder {decoy!r} wrongly flagged: {bad}"


def test_example_email_not_flagged():
    found = scanner.scan("contact: jane@example.com")
    assert not any(f["type"] == "pii_email" for f in found)


def test_real_email_flagged_low():
    found = scanner.scan("user real-customer@acmehealth.com signed up")
    assert any(f["type"] == "pii_email" and f["severity"] == "low" for f in found)


# --- redact -------------------------------------------------------------------------

def test_redact_replaces_secret_and_is_offset_safe():
    secret = "ghp_" + "Z" * 36
    text = f"a={secret}; b=AKIAZ8R7QWERTYUIOPAS; done"
    found = scanner.scan(text)
    out = scanner.redact(text, found)
    assert secret not in out
    assert "AKIAZ8R7QWERTYUIOPAS" not in out
    assert "redacted" in out
    assert out.startswith("a=") and out.endswith("; done")


def test_redact_empty_findings_is_identity():
    assert scanner.redact("nothing here", []) == "nothing here"


# --- merge / de-overlap -------------------------------------------------------------

def test_overlapping_findings_keep_higher_severity():
    f_low = {"type": "high_entropy_string", "span": [10, 30], "severity": "medium",
             "reason": "", "redaction": "X", "source": "rules"}
    f_high = {"type": "github_token", "span": [10, 30], "severity": "critical",
              "reason": "", "redaction": "Y", "source": "rules"}
    merged = scanner.merge_findings([f_low, f_high])
    assert len(merged) == 1
    assert merged[0]["type"] == "github_token"


def test_nonoverlapping_findings_all_survive():
    a = {"type": "x", "span": [0, 5], "severity": "high", "reason": "", "redaction": "R",
         "source": "rules"}
    b = {"type": "y", "span": [6, 9], "severity": "low", "reason": "", "redaction": "R",
         "source": "rules"}
    assert len(scanner.merge_findings([a, b])) == 2


# --- semantic pass (injected model — deterministic) ---------------------------------

def test_semantic_maps_model_findings(semantic_on):
    text = "the staging box is at prod-db-7.internal.acme and owner is bob@acme.com"
    canned = (
        '[{"snippet": "prod-db-7.internal.acme", "type": "internal_hostname", '
        '"severity": "high", "reason": "internal production hostname"}]'
    )
    out = semantic.scan_semantic(text, call_model=lambda _p: canned)
    assert len(out) == 1
    f = out[0]
    assert f["type"] == "internal_hostname"
    assert f["source"] == "semantic"
    assert text[f["span"][0]:f["span"][1]] == "prod-db-7.internal.acme"


def test_semantic_skips_snippet_not_in_text(semantic_on):
    out = semantic.scan_semantic(
        "clean text",
        call_model=lambda _p: '[{"snippet": "not present", "type": "x", "severity": "low", "reason": ""}]',
    )
    assert out == []


def test_semantic_drops_rules_owned_types(semantic_on):
    # model re-reports an AWS key by vendor type → semantic layer yields to rules
    out = semantic.scan_semantic(
        "AKIAZ8R7QWERTYUIOPAS",
        call_model=lambda _p: '[{"snippet": "AKIAZ8R7QWERTYUIOPAS", "type": "aws_access_key_id", "severity": "high", "reason": ""}]',
    )
    assert out == []


def test_semantic_tolerates_markdown_wrapped_json(semantic_on):
    text = "secret token foobar123"
    wrapped = '```json\n[{"snippet": "foobar123", "type": "token", "severity": "medium", "reason": "x"}]\n```'
    out = semantic.scan_semantic(text, call_model=lambda _p: wrapped)
    assert len(out) == 1 and out[0]["type"] == "token"


def test_semantic_junk_response_is_empty_not_crash(semantic_on):
    assert semantic.scan_semantic("x", call_model=lambda _p: "I could not find anything!") == []


def test_semantic_model_exception_degrades_to_empty(semantic_on):
    def boom(_p):
        raise OSError("model down")
    assert semantic.scan_semantic("anything", call_model=boom) == []


def test_semantic_disabled_via_env(monkeypatch):
    monkeypatch.setenv("LEAKPROOF_SEMANTIC", "0")
    called = []
    semantic.scan_semantic("x", call_model=lambda p: called.append(p) or "[]")
    assert called == []  # transport never invoked when disabled


# --- integration: scan() merges rules + semantic ------------------------------------

def test_scan_combines_rules_and_semantic(semantic_on):
    text = "key=AKIAZ8R7QWERTYUIOPAS host=prod-db-7.internal.acme"
    canned = '[{"snippet": "prod-db-7.internal.acme", "type": "internal_hostname", "severity": "high", "reason": "x"}]'
    found = scanner.scan(text, call_model=lambda _p: canned)
    types = {f["type"] for f in found}
    assert "aws_access_key_id" in types
    assert "internal_hostname" in types


def test_entropy_helper_sane():
    assert rules.shannon_entropy("aaaaaaaa") < 1.0
    assert rules.shannon_entropy("Zx9QkP7mWvL2nR8tY4uH6jB3cF5dG1sA") > 3.5


# --- hardened detectors (credit card / phone / test-key / hash / bulk paste) ---------

def test_credit_card_luhn_valid_caught():
    found = scanner.scan("charge.create(number='5500005555555559', exp='04/27')")
    assert any(f["type"] == "credit_card" and f["severity"] == "high" for f in found)


def test_vendor_test_card_not_flagged():
    # famous Stripe test PAN — must not read as a cardholder leak
    found = scanner.scan("test charge with card 4242 4242 4242 4242")
    assert not any(f["type"] == "credit_card" for f in found)


def test_phone_number_caught():
    found = scanner.scan("cell +1 415 555 0179 call me")
    assert any(f["type"] == "pii_phone" and f["severity"] == "medium" for f in found)


def test_stripe_test_key_is_low_not_blocking():
    found = scanner.scan("STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc  # test mode")
    blocking = [f for f in found if f["severity"] in ("critical", "high", "medium")]
    assert not blocking, f"test key should not block: {blocking}"
    assert any(f["type"] == "vendor_test_key" for f in found)


def test_git_sha_not_flagged_as_secret():
    found = scanner.scan("commit = 'a3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5'  # git sha")
    assert not any(f["severity"] in ("critical", "high", "medium") for f in found)


def test_bulk_source_paste_flagged():
    blob = "\n".join(f"def _handler_{i}(req): return process(req)" for i in range(40))
    found = scanner.scan("here is the whole module:\n" + blob)
    assert any(f["type"] == "bulk_source_paste" for f in found)


def test_bulk_marker_is_zero_width_and_not_redacted():
    blob = "\n".join(f"def _handler_{i}(req): return process(req)" for i in range(40))
    text = "module:\n" + blob
    found = scanner.scan(text)
    bulk = [f for f in found if f["type"] == "bulk_source_paste"]
    assert bulk and bulk[0]["span"] == [0, 0]
    # zero-width marker must not mutate the body on redact
    assert scanner.redact(text, bulk) == text


def test_assignment_does_not_merge_lhs_into_token():
    # NAME=sk_test_... must split so test-key suppression sees the sk_test_ prefix
    found = scanner.scan("OPENAI_TEST=sk_test_abcdefghijklmnop1234")
    assert not any(f["type"] == "high_entropy_string" for f in found)
