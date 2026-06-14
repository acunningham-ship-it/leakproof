<!-- DRAFT launch asset. Name = leakproof (pending final on-disk rename). Drop in alongside README + LICENSE. -->

# Contributing to leakproof

The fastest way to help: throw a secret at it that it misses, or a clean string it wrongly flags. Both are bugs, and the second kind matters as much as the first. A scanner that cries wolf gets uninstalled.

## Running it locally

```bash
git clone <repo> && cd leakproof
uv sync --group dev
uv run pytest -q
```

Python 3.12+. The test suite runs with no model and no network. The semantic layer wants `ollama` with `qwen2.5:1.5b` pulled; without it, the regex and entropy detectors still run and still pass their tests.

## The one rule that isn't negotiable

No code path may send scanned content anywhere off the machine. Not for telemetry, not for a "smarter" cloud check, not for crash reporting. The entire reason this tool exists is that it doesn't do that. A PR that adds an outbound call touching scanned text gets closed, no matter how good the feature is. If you want a network feature, it goes behind an explicit opt-in flag that's off by default and documented loudly.

## Adding a detector

Most contributions are new detectors, and they're the easy kind to review. A detector takes text and returns findings against the locked shape:

```python
Finding = {
    "type": str,          # "aws_secret_key", "stripe_key", "pii_email", ...
    "span": [start, end],  # char offsets
    "severity": "critical" | "high" | "medium" | "low",
    "reason": str,         # why this fired, in plain English
    "redaction": str,      # what replaces it
    "source": "rules" | "semantic",
}
```

Two things make a detector mergeable:

1. A real positive case in `tests/adversarial/corpus.py` (use a fake-but-valid-shaped secret, never a real one).
2. A decoy in the same file that looks similar and must NOT fire. AWS's own `AKIAIOSFODNN7EXAMPLE`, a placeholder, a git SHA, a test card number. If your detector flags those, it's not ready.

The bar is zero false-passes on the corpus and zero false-positives on the decoys. The scorecard (`uv run python tests/adversarial/scorecard.py`) prints both.

## Pull requests

Keep them small and single-purpose. One detector, one fix, one surface. Say what you tested and paste the scorecard line if you touched detection. If you're adding support for a new AI tool to wrap, include the env-var recipe and which tool version you verified it against, because those shift.

Issues: a missed leak or a false flag, with the smallest input that reproduces it, is the most useful thing you can file.
