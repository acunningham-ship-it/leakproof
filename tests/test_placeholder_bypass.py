"""Regression for the FN-03/04 placeholder-suppression bypass (bughunt-leakproof 2026-06-20).

The old prefix-wildcards (`my[_-]?\\w+`, `(test|example|...)[\\w-]*`, contains-`example`) swallowed REAL
secrets and were an intentional-bypass vector ("annotate a real key with 'example' to evade detection").
A real secret that merely STARTS WITH or CONTAINS a placeholder word must be CAUGHT; genuine placeholders,
masked tokens, and doc decoys must stay suppressed (the "0 false-positive on decoys" claim).
"""
from leakproof.scanner.rules import _is_placeholder


# real secrets that the old code wrongly swallowed — must NOT be treated as placeholders
REAL_SECRETS_MUST_CATCH = [
    "myActualRealProductionKey1234567890AbCdEf",    # FN-03: `my` prefix
    "MyS3cr3tP4ssw0rd",                             # FN-03
    "myProductionSecret123456789012345678901",      # FN-03
    "testEnv_RealActualSecret12345678",             # FN-04: `test` prefix
    "fake_but_this_is_production_test_key_12345",    # FN-04: `fake` prefix
    "sk-ant-api03-f7bKm3Ns9pXeXaMpLe01234",          # FN-04b: contains 'example' in random bytes
    "sk-ant-api03-f7bKm3Ns9example01234567",         # FN-04b
]

# genuine placeholders / masked tokens / doc decoys that MUST stay suppressed (0-FP claim)
GENUINE_PLACEHOLDERS_MUST_SUPPRESS = [
    "my_api_key", "my_secret", "your_secret_key", "test_key", "test-token", "TEST_TOKEN",
    "example_key", "changeme", "placeholder", "redacted", "<your-key-here>", "${ENV_VAR}",
    "xxxx", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",   # masked token (long x-run)
    "AKIAIOSFODNN7EXAMPLE",                                # AWS documentation key
]


def test_real_secrets_with_placeholder_words_are_not_suppressed():
    for v in REAL_SECRETS_MUST_CATCH:
        assert _is_placeholder(v) is False, f"BYPASS REGRESSION: {v!r} wrongly suppressed as a placeholder"


def test_genuine_placeholders_still_suppressed():
    for v in GENUINE_PLACEHOLDERS_MUST_SUPPRESS:
        assert _is_placeholder(v) is True, f"{v!r} should be suppressed as a placeholder (0-FP claim)"
