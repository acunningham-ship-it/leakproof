# leakproof

**Local-first secret firewall for AI coding assistants.**

Your security team banned Claude Code or Cursor over data egress. Here's the local technical control that lets you turn them back on.

leakproof sits between the tool and the model API and reads every outbound request before it leaves the machine. Finds a secret, it redacts it or kills the request. Nothing hits the cloud. The decision happens on your laptop, which is the only setup that isn't self-defeating — you don't hand a key to a stranger to ask them whether it's a key.

Two ways to run it:

```bash
# wrap your AI tool: everything it sends gets scanned + cleaned first
leakproof run -- claude
leakproof run -- aider

# guard the repo itself: stop secrets before they reach a commit
leakproof install-hook
```

## Who it's for

Compliance-bound teams under SOC 2 / HIPAA / ITAR / GDPR whose security team blocked AI coding tools because the tools exfiltrate working-tree context — including any secrets in open files — to a cloud API. leakproof is the local technical control and audit trail that satisfies the objection.

The alternative tools (GitGuardian's ggshield recently added Claude Code and Cursor hooks) require a cloud account: scan metadata leaves the machine. That's structurally off the table for the shops that most need this. leakproof has zero cloud dependency — no account, no API key, no telemetry, nothing leaves the building.

## What it catches

163 tests, including a 23-case adversarial suite. Rules-only pass: 14/14 planted leaks caught, 0/9 false-positives on decoys (AWS doc-example keys, git SHAs, env *reads* without literals — all correctly ignored).

Catches on the first pass (no local model needed): AWS access keys and secret keys, GitHub/OpenAI/Anthropic/Stripe tokens, JWTs, PEM private keys, raw `.env` values, high-entropy blobs, email, phone, card numbers.

The second pass is optional — a local-model semantic check (qwen2.5:1.5b via ollama) that reads the value rather than the variable name. That's where keyword scanners break down.

### Compared to detect-secrets

detect-secrets is a common pre-commit baseline. It uses keyword matching plus entropy on a per-line basis.

| Scenario | detect-secrets | leakproof |
|---|---|---|
| `AWS_SECRET_ACCESS_KEY=abc123…` in config | ✅ caught | ✅ caught |
| AWS-shaped 40-char string in a prose comment (no `=` anchor, no keyword) | ❌ missed | ✅ caught (entropy) |
| Live DB connection string in a test fixture with a neutral var name | ❌ missed | ✅ caught (entropy) |
| Base64-wrapped token, benign-looking variable name | ❌ missed | ✅ caught (entropy) |
| Bulk source paste containing a buried credential | ❌ missed | ✅ caught |
| `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"` (AWS doc placeholder) | ⚠️ may flag | ✅ ignored (EXAMPLE marker) |
| `sha256:e3b0c44298fc…` git SHA | ✅ ignored | ✅ ignored |

The honest framing: leakproof catches what keyword scanners miss **when the variable name is benign**. The local-model semantic pass is opt-in and additive — you get the full regex+entropy layer with or without it.

## Install

```bash
# install the CLI (zero-dependency core)
pipx install leakproof

# …or run it without installing anything:
uvx leakproof run -- claude
```

Python 3.10+. The proxy surface needs `aiohttp`:

```bash
pipx install "leakproof[proxy]"
```

Prefer the bleeding edge? Install straight from the repo — the source *is* the package:

```bash
pipx install git+https://github.com/acunningham-ship-it/leakproof.git
```

## How it works

`leakproof run -- claude` sets `ANTHROPIC_BASE_URL` (or `OPENAI_API_BASE` for aider) to a local proxy on `127.0.0.1:8747`, then launches the tool. The proxy reads each request body, runs the scanner, forwards a redacted copy upstream, and streams the response back untouched. No certificate to install, no system-wide proxy, no interception of anything you didn't ask it to wrap.

Every catch lands in an append-only audit log at `~/.local/share/leakproof/audit.jsonl`. `leakproof watch` tails it:

```
$ leakproof watch
  14:02:11  claude-code → api.anthropic.com   redacted   aws_secret_key (critical)
  14:02:11  claude-code → api.anthropic.com   redacted   STRIPE_SECRET_KEY from .env
  14:06:48  aider       → api.openai.com      blocked    private_key (PEM)

  this session: 3 secrets stopped, 0 reached the cloud
```

## Modes

`monitor` — logs only, nothing changes. Use this first to see what's been leaving without disrupting your workflow.

`redact` — swaps each finding for a placeholder and forwards the cleaned request. Default.

`block` — rejects the request outright with a 403 and names what would have leaked.

## Free

Apache-2.0, no paid tier, no account, no wall. One developer or a whole compliance team, same binary.

## Status

Works today: Claude Code and aider (any tool that honors a base-URL env var). Cursor and Copilot use proprietary backends that need a real HTTPS intercept proxy and a cert install — that's v1.1, not v1. One machine, no daemon, no telemetry.

Apache-2.0. Built by [hamstudios](https://github.com/hamstudios). Issues and PRs welcome.
