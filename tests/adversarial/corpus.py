"""Adversarial leak corpus for tripwire's scanner (QA lane / worker-3).

This is the credibility backbone of a DLP tool: a security scanner is only as good as its
false-PASS rate (a real secret it lets through) and its false-POSITIVE rate (clean code it
blocks). This corpus pins both.

Two case kinds:
  * LEAK  — content that MUST be caught (>=1 finding). A leak with zero findings = a false-pass,
            the cardinal sin. The harness asserts false-pass == 0.
  * DECOY — content that must NOT fire (placeholders, documented example keys, env *reads* rather
            than literals). A decoy that fires = a false-positive (annoying, erodes trust).

Several leaks are deliberately ones plain regex scanners (gitleaks/trufflehog) MISS — base64/
hex-obfuscated keys, a real-looking secret in prose, a live DB URL in a test fixture — to show
where the local-model semantic pass earns its place. Those are tagged `regex_misses=True`.

⚠️ EVERY secret below is SYNTHETIC — randomly constructed in the right *format* but not a real
credential. Do not "fix" them to be valid; they exist to be detected, never used.

Contract under test (locked with opus-2, scanner lane):
    scan(text, context=None) -> [ {type, span:[start,end], severity, reason, redaction}, ... ]
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Case:
    id: str
    kind: str                       # "leak" | "decoy"
    text: str
    expect_types: list[str] = field(default_factory=list)  # leaks: type hints the scanner ideally tags
    regex_misses: bool = False      # True if a naive regex/entropy scanner would miss this leak
    note: str = ""


# --- LEAKS: must be caught (>=1 finding) ------------------------------------------------------
LEAKS: list[Case] = [
    Case(
        "aws_access_key_id",
        "leak",
        "deploy script:\n  export AWS_ACCESS_KEY_ID=AKIA2E0A8F3B9C1D7K4P\n",
        ["aws_access_key"],
        note="canonical AKIA-prefixed access key id",
    ),
    Case(
        "aws_secret_in_prose",
        "leak",
        "Hey, the staging secret is wJa1rXUtnF3MI4K7MDENGbPxRf9CYZ8qLm2Vt0Bn — don't share it.",
        ["aws_secret_key"],
        regex_misses=True,
        note="40-char AWS-secret-shaped string in a sentence, no key=value anchor (and NO 'EXAMPLE' "
             "marker — a clean leak, not a decoy collision). Semantic/entropy win.",
    ),
    Case(
        "github_pat",
        "leak",
        "+ GH_TOKEN = 'ghp_R8kQ2mZ1nP7wV3xL9tD0cF6jH4bN5sA1eY8u'\n",
        ["github_token"],
        note="GitHub personal access token (ghp_ + 36)",
    ),
    Case(
        "openai_key",
        "leak",
        'OPENAI_API_KEY="sk-proj-aZ09Xy7Qw2Er5Ty8Ui1Op3As6Df9Gh2Jk5Lz8Xc1Vb4Nm7Qw0"\n',
        ["openai_key"],
        note="OpenAI sk-proj key",
    ),
    Case(
        "anthropic_key",
        "leak",
        "client = Anthropic(api_key='sk-ant-api03-Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe9Dc8Ba7-_Qw2Er')\n",
        ["anthropic_key"],
        note="Anthropic sk-ant key",
    ),
    Case(
        "stripe_live",
        "leak",
        "STRIPE_SECRET=sk_live_51Mx9aQ2eRtYuIoP3aSdFgHjKlZxCvBnM\n",
        ["stripe_key"],
        note="Stripe LIVE secret key (sk_live_) — high severity",
    ),
    Case(
        "jwt",
        "leak",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n",
        ["jwt"],
        note="signed JWT (3 base64url segments)",
    ),
    Case(
        "pem_private_key",
        "leak",
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEArandomlookingbase64paddingdatahereforthetestfixture0\n"
        "9z8Y7x6W5v4U3t2S1r0Q9p8O7n6M5l4K3j2I1h0G9f8E7d6C5b4A3210zyxwvut==\n"
        "-----END RSA PRIVATE KEY-----\n",
        ["private_key"],
        note="PEM private key block",
    ),
    Case(
        "db_url_in_test_fixture",
        "leak",
        "# tests/fixtures/conftest.py\nDB = 'postgres://svc_app:Pr0dPassw0rd!@db.prod.internal:5432/payments'\n",
        ["connection_string"],
        regex_misses=True,
        note="a LIVE-looking prod DB URL hiding in a test fixture — semantic catch",
    ),
    Case(
        "base64_wrapped_aws",
        "leak",
        "config_blob = 'QUtJQTJFMEE4RjNCOUMxRDdLNFA='  # looks like opaque config\n",
        ["aws_access_key", "obfuscated_secret"],
        regex_misses=True,
        note="base64-wrapped AKIA key in a non-keyword var — keyword/entropy scanners (gitleaks) "
             "don't fire on the var name; win is VALUE inspection, not 'regex can't do base64' "
             "(gitleaks v8.30.1 catches it via entropy if the var is named like a secret — verified)",
    ),
    Case(
        "slack_webhook",
        "leak",
        "SLACK_HOOK=https://hooks.slack.com/services/T00000000/B11111111/aZ09bY18cX27dW36eV45fU54\n",
        ["slack_webhook"],
        note="Slack incoming-webhook URL (token in path)",
    ),
    Case(
        "pii_email_phone",
        "leak",
        "patient: Maria Gonzalez, dob 1984-03-11, cell +1 415 555 0179, mgonzalez84@gmail.com\n",
        ["pii_email", "pii_phone"],
        note="real-looking PII (name+dob+phone+personal email) — the clinic/DLP angle",
    ),
    Case(
        "credit_card",
        "leak",
        "charge.create(number='5500005555555559', exp='04/27', cvc='913')\n",
        ["pii_credit_card"],
        note="a Luhn-valid-format PAN (not a vendor test card)",
    ),
    Case(
        "full_file_paste",
        "leak",
        "Here's our whole auth module so you have context:\n"
        + "\n".join(f"def _internal_handler_{i}(req, secret_salt='s4lt'): ..." for i in range(40)),
        ["full_file_leak"],
        regex_misses=True,
        note="bulk proprietary-source paste — no single token, but a whole-file exfil heuristic should flag volume",
    ),
]


# --- DECOYS: must NOT fire (false-positive guard) --------------------------------------------
DECOYS: list[Case] = [
    Case(
        "aws_documented_example",
        "decoy",
        "see AWS docs: AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        note="AWS's OWN documented example key — the literal 'EXAMPLE' marks it; regex flags it, a good scanner shouldn't",
    ),
    Case(
        "placeholder_your_key",
        "decoy",
        'OPENAI_API_KEY="sk-your-api-key-here"   # fill this in\n',
        note="obvious placeholder",
    ),
    Case(
        "xxx_redacted_token",
        "decoy",
        "GH_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
        note="masked/redacted token (all x's)",
    ),
    Case(
        "env_read_not_literal",
        "decoy",
        "db_password = os.environ['DB_PASSWORD']  # read from env, no secret in source\n",
        note="reads a secret from env — there is NO literal secret here; naive scanners over-trigger on the word 'password'",
    ),
    Case(
        "stripe_test_key",
        "decoy",
        "STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc  # test mode only\n",
        note="Stripe TEST key (sk_test_) — not a live credential; at most low/info severity, should not BLOCK",
    ),
    Case(
        "example_dot_com_email",
        "decoy",
        "contact: support@example.com (placeholder address)\n",
        note="example.com address — not PII",
    ),
    Case(
        "vendor_test_card",
        "decoy",
        "test charge with Stripe's card 4242 4242 4242 4242\n",
        note="vendor's well-known test PAN — not a real cardholder leak",
    ),
    Case(
        "high_entropy_but_benign",
        "decoy",
        "commit = 'a3f9c1e8b7d62049f5e1c0a8b4d7e2f6c9a1b3d5'  # git sha\n",
        note="40-hex git SHA — high entropy, but not a secret; entropy-only scanners false-positive here",
    ),
    Case(
        "uuid",
        "decoy",
        'request_id = "550e8400-e29b-41d4-a716-446655440000"\n',
        note="a UUID — structured, not secret",
    ),
]


ALL: list[Case] = LEAKS + DECOYS
