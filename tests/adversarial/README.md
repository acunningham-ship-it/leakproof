# tripwire — adversarial QA lane

The credibility backbone of a DLP tool. A leak scanner is judged on two numbers:

- **false-pass** — a real secret it lets through. Cardinal sin. Gate requires **0**.
- **false-positive** — clean code it blocks. Erodes trust. Gate requires **0** *blocking* hits
  (a low/info note on, say, a Stripe **test** key is fine; blocking the commit is not).

## Files

| File | What |
|------|------|
| `corpus.py` | 14 leaks (incl. 4 a plain regex scanner MISSES) + 9 decoys, each labelled. All secrets are **synthetic**. |
| `harness.py` | Pure scoring logic: `run(scan_fn) -> Report`. Decoupled from the scanner (takes `scan` as an arg). |
| `scorecard.py` | Runnable report + CI gate: `uv run python tests/adversarial/scorecard.py`. |
| `test_harness_selftest.py` | Proves the harness is correct *today* with a fake scanner (green before the real scanner lands). |
| `test_scanner_adversarial.py` | The real gate. `importorskip`s the scanner → skips until it's merged, then hard-fails on any false-pass/positive. |
| `demo_planted_secret.diff` | The **Show HN demo fixture** — a diff a dev might really commit. |

## The contract (locked with the scanner lane, opus-2)

```
scan(text, context=None) -> [ {type, span:[start,end], severity, reason, redaction}, ... ]
```
A finding **blocks** at severity `medium`+. Leaks must yield ≥1 blocking finding; decoys must yield 0.

## The Show HN demo (`demo_planted_secret.diff`)

**VERIFIED framing** (opus-3 ran gitleaks v8.30.1 on this exact fixture — reproducible:
`gitleaks detect --no-git --source <dir>`). Use this story; it survives a hostile HN reader:

> Regex/keyword scanners like gitleaks key off **variable names + entropy**. On this demo diff the
> secrets live in innocuously-named fields (`_aws`, `_aws_secret`, `_fallback`, `DB`) → **gitleaks
> reports 0 findings**. leakproof flags all of them because it evaluates the **VALUE, not the variable
> name** — it recognizes an AWS key, a base64-wrapped key, and a live Postgres DSN no matter what
> they're called.

That's **value-awareness vs keyword-matching** — true, demoable, and renaming-proof.

**Do NOT claim** "gitleaks can't see base64" — that's false. Empirically, when the vars are renamed
to keyword-y names (`aws_secret_access_key=`, `database_password_url=`), gitleaks DOES catch the
base64 blob and the DB URL via its entropy rule (it never decodes base64 — the var name is what cues
it). So the differentiator is **var-name independence / value inspection**, not "regex can't do base64."

Honest screenshot: **gitleaks 0 → leakproof 3** on the fixture as-written, with the one-line reason
(value vs variable-name). Verified, not asserted. (Thanks opus-3 for running the real numbers.)

## Run

```bash
uv run pytest tests/adversarial -q          # harness self-tests pass now; scanner gate skips until merged
uv run python tests/adversarial/scorecard.py
```

## Status

Corpus + harness + gate: **done, green** (self-tests pass; scanner gate armed & skipping until
opus-2's `tripwire.scanner.scan` merges). Then it's a hard pre-merge gate. Owner: worker-3.
