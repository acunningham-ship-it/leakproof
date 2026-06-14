<!-- NAME PENDING FINAL LOCK: front-runner `leakproof` (free on npm+pypi+leakproof.sh; airlock & leakproof both collide). Alt: `noexfil`. On-disk package still `leakproof` until the rename sweep. DRAFT — every claim below gets checked against the real build before anything ships public. -->

# leakproof

Your AI coding tool sends more than you think.

When Claude Code or aider answers a question, it ships context to the cloud: open files, your `.env`, whatever in the working tree it decided was relevant. Most of the time that's harmless. The time it isn't is the time it quietly folds in `AWS_SECRET_ACCESS_KEY=...` from a config file you forgot was open in the next tab.

leakproof sits between your editor and the API and reads every outbound request before it leaves the machine. Finds a secret, it redacts it or kills the request. The decision happens locally, which for a secret scanner is the only setup that isn't self-defeating. You don't hand a key to a stranger to ask them whether it's a key.

Two ways to run it:

```bash
# wrap your AI tool: everything it sends gets scanned + cleaned first
leakproof run -- claude
leakproof run -- aider

# or guard the repo itself: stop secrets before they reach a commit
leakproof install-hook
```

## What it catches

Fast path is regex plus entropy, no model needed: AWS keys, GitHub / OpenAI / Anthropic / Stripe tokens, JWTs, PEM private keys, raw `.env` values, high-entropy blobs, and the obvious PII (email, phone, card numbers).

The second pass is the one keyword scanners miss. Tools like gitleaks mostly decide by the name around a value: a field called `AWS_SECRET_KEY` lights up, the same key in a field called `_aws` often slides through. leakproof's optional local-model pass (qwen2.5 1.5B on ollama) reads the value instead, so it catches a live database DSN, a real customer's email parked in a fixture, or a credential whose field was named to look harmless. Skip the model and you keep the regex and entropy layer; the value-aware pass adds to it, it isn't load-bearing.

## Why local is the whole point

A cloud secret-scanner has to receive your secret in order to scan it. That's the problem written twice. leakproof never ships the thing it's guarding anywhere.

It's also the only version some teams are allowed to run. Banks, hospitals, defense shops, anyone living under GDPR: their security team already said no to piping source through OpenAI, so they get no Copilot, no cloud review, no cloud anything. They've been picking between current tooling and their own policy. A scanner that runs entirely on the developer's laptop doesn't make them pick.

## Install

```bash
uvx leakproof          # nothing to install, just runs
# or
pipx install leakproof
```

Python 3.12+. The proxy binds `127.0.0.1:8747` and forwards to the real API; the tool you wrap never knows it's there past one env var.

## How it works

`leakproof run -- claude` points `ANTHROPIC_BASE_URL` (or `OPENAI_API_BASE`, for aider) at a local proxy, then launches the tool. The proxy reads each request body, runs the scanner, forwards a redacted copy upstream, and streams the response straight back untouched. No certificate to trust, no system-wide proxy, no intercept of anything except the one tool you asked it to wrap.

Every catch goes to an append-only log at `~/.local/share/leakproof/audit.jsonl`. `leakproof watch` tails it and keeps a running count of what didn't get out:

```
$ leakproof watch
  14:02:11  claude-code → api.anthropic.com   redacted   aws_secret_key (critical)
  14:02:11  claude-code → api.anthropic.com   redacted   STRIPE_SECRET_KEY from .env
  14:06:48  aider       → api.openai.com      blocked    private_key (PEM)

  this session: 3 secrets stopped, 0 reached the cloud
```

## Modes

`monitor` logs and changes nothing, so you can watch what's been leaving without breaking your flow. `redact` swaps each finding for a placeholder and forwards the cleaned request; that's the default. `block` rejects the request outright with a 403 that names what would have leaked.

## Free, and the paid part

The CLI is MIT and free, runs solo, needs no account. One developer never hits a wall.

The paid tier is a team thing: one shared redaction policy everybody inherits, a central audit log instead of a file per laptop, and a CI check that fails the build when a secret would have shipped. That last one is what a security lead actually wants to buy.

## Status

Pre-launch, and built in a hurry (the commit history won't hide it). Tools that honor a base-URL env var work now: Claude Code, aider. GUI editors like Cursor and Copilot talk to their backends differently and need a real proxy plus a cert; that's a fast-follow, not v1. One machine, no daemon, no telemetry.

MIT. Issues and PRs welcome once the repo's public.
