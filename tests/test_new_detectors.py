"""Coverage for the provider detectors added in the 2026-06 hardening pass.

Tests the deterministic regex layer (rules.scan_rules) directly, so results never
depend on the optional semantic LLM pass (which may re-label a vendor type to a
generic one like 'secret_key'). Samples are fake-but-valid-shaped, not real secrets.
"""
import pytest
from leakproof.scanner import rules

H = "0123456789abcdef"

NEW_DETECTORS = {
    "gitlab_token":       "tok = glpat-" + "A" * 24,
    "npm_token":          "//_authToken=npm_" + "a" * 36,
    "pypi_token":         "pypi-AgE" + "B" * 52,
    "sendgrid_key":       "SG." + "A" * 22 + "." + "B" * 43,
    "huggingface_token":  "hf_" + "a" * 36,
    "twilio_api_key":     "SK" + H * 2,
    "digitalocean_token": "dop_v1_" + H * 4,
    "square_token":       "sq0atp-" + "A" * 24,
    "shopify_token":      "shpat_" + H * 2,
    "postman_key":        "PMAK-" + "a" * 24 + "-" + "b" * 34,
    "linear_key":         "lin_api_" + "a" * 44,
    "mailgun_key":        "key-" + H * 2,
    "telegram_bot_token": "123456789:" + "A" * 35,
    "azure_storage_key":  "AccountKey=" + "A" * 86 + "==",
}


def _types(text):
    return [f["type"] for f in rules.scan_rules(text)]


@pytest.mark.parametrize("expected_type,text", list(NEW_DETECTORS.items()))
def test_new_detector_fires(expected_type, text):
    assert expected_type in _types(text), f"{expected_type} not detected in {text!r}"


def test_new_detectors_no_false_positive_on_benign_code():
    benign = 'def main():\n    count = 42\n    msg = "hello world"\n    return msg\n'
    assert _types(benign) == [], f"unexpected findings on benign code: {_types(benign)}"
