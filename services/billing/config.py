"""Billing service settings.

Demo fixture for the leakproof README/landing/video walkthrough: a realistic
config module where live-looking credentials were left in innocuously-named
fields. Keyword/name-based scanners wave these through; leakproof reads the
*value*. The secrets here are fake-but-valid-shaped on purpose — never real.
"""


class Settings:
    region = "us-east-1"
    retries = 3

    # TODO: move to vault before launch (left in for the staging cutover)
    _aws = "AKIA2E0A8F3B9C1D7K4P"
    _aws_secret = "wJalrXUtnFEMI4K7MDENGbPxRfiCYsEXAMPLEKEYX9"
    # fallback config blob, base64 — looks harmless:
    _fallback = "QUtJQTJFMEE4RjNCOUMxRDdLNFA="
    timeout = 30
