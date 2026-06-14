<!-- DRAFT demo script for the GIF + the live Show HN demo. Uses worker-3's planted-secret corpus (tests/adversarial/) and worker-opus-4's `leakproof watch` TUI. Record from the REAL tool once the lanes land — no faked terminal output, HN will spot it. -->

# Demo: the planted-secret reveal

Goal of the demo: in under 20 seconds, show a real secret trying to leave and getting stopped, then show the thing regex scanners miss. Two beats. The first sells the idea, the second sells why it isn't just gitleaks.

Keep it one terminal, large font, no editor chrome. The whole point is that it's boring infrastructure doing something you didn't know you needed.

## Setup (off-camera)

A throwaway repo with two planted leaks (pull the exact values from worker-3's `tests/adversarial/` fixtures so the demo and the test suite agree):

- `.env` containing a live-looking `STRIPE_SECRET_KEY` and `AWS_SECRET_ACCESS_KEY`
- `config/db.py` with a hardcoded production-shaped Postgres URL (`postgres://app:hunter2@prod-db.internal:5432/...`) — this is the one regex tools wave through

Have ollama running with `qwen2.5:1.5b` pulled, so the semantic pass is live on the box.

## Beat 1 — the proxy catches a key mid-request (the GIF)

Split the terminal. Left: the AI tool. Right: `leakproof watch`.

```
$ leakproof run -- claude
  proxy on 127.0.0.1:8747  ·  mode: redact  ·  watching outbound

> read config/.env and tell me what services this app talks to
```

The moment Claude reads `.env` into context and sends it, the right pane lights up:

```
$ leakproof watch
  14:02:11  claude-code → api.anthropic.com   redacted   AWS_SECRET_ACCESS_KEY (critical)
  14:02:11  claude-code → api.anthropic.com   redacted   STRIPE_SECRET_KEY (critical)

  this session: 2 secrets stopped, 0 reached the cloud
```

Claude still answers the question. It just answered it with `‹AWS_SECRET_ACCESS_KEY redacted›` where the key used to be. That contrast is the whole demo: the answer is fine, the key never left.

If you can show the actual outbound body diff (what the tool tried to send vs what the proxy forwarded), do it — that's the screenshot people share.

## Beat 2 — value-awareness vs keyword-matching (the "not just gitleaks" point)

Get this one exactly right, because a security crowd will rerun your demo within ten comments. opus-3 did the homework: gitleaks v8.30.1 on the demo fixture reports 0 findings. That's true and reproducible, and worth showing. The reason it's 0 is the actual pitch, so explain it instead of waving at it.

gitleaks leans on a `generic-api-key` rule that keys off the variable name plus entropy. In the fixture the secrets live in innocuously-named fields (`_aws`, `_aws_secret`, `DB`, a bare base64 blob), so nothing cues the keyword rule and it returns nothing. Rename those fields to something like `aws_secret_access_key=` and gitleaks' entropy check does start catching them. So do not claim "regex structurally can't see this." Claim the thing that's actually true:

> Keyword scanners decide by what a secret is *named*. leakproof decides by what it *is*.

leakproof reads the value. It recognizes an AWS key, a base64 blob that decodes to one, and a live Postgres DSN no matter what the surrounding field is called. That claim survives a hostile reader renaming things on stage; the "gitleaks finds zero" claim does not.

```
$ gitleaks detect --source tests/fixtures/conftest.py --no-banner
  no leaks found

$ leakproof scan tests/fixtures/conftest.py
  conftest.py:9    high  db_url   live Postgres DSN (prod-db.internal)
  conftest.py:14   high  aws_key  AWS secret key, base64-wrapped
```

The value-aware catches lean on the local model, and a 1.5B will miss some; say so. Don't claim a catch rate. Keep the fixture's original field names in the demo on purpose, because the harmless-looking name is exactly what makes the point.

## What NOT to fake

- Don't pre-write the terminal output. Record the real run. If the real `watch` output looks different from what's above, update this file to match it (ping worker-opus-4 for the actual TUI lines).
- Don't use a real key you care about, obviously. The fixtures are fake-but-valid-shaped on purpose.
- Don't claim a catch rate or a benchmark number we haven't measured. "catches things regex misses" is a claim we can show; "catches 98% of leaks" is one we can't.

## Recording notes

- `asciinema` for the terminal, then `agg` to a GIF, keeps it crisp and small for the README/landing.
- Target 15–20s. Loop-friendly. No music.
- One take of Beat 1 is the hero asset. Beat 2 is a still or a second short clip.
