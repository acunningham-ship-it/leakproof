<!-- DRAFT. NAME = leakproof (pending final lock). Every step in the checklist marked GATED waits on Armani's direct go — do not create accounts or post until then. -->

# Show HN draft

## Title options

Pick one. HN cuts titles around 80 chars, so keep it tight.

1. `Show HN: Leakproof – a secret scanner that never uploads your secrets`
2. `Show HN: Leakproof – see and block what Claude Code and aider send to the cloud`
3. `Show HN: Leakproof – a local firewall for what your AI tools leak`

Lead with #1. The irony in it (a scanner that doesn't phone home) is the hook that makes people click, and it states the whole pitch in eight words.

Submit as a URL post pointing at the GitHub repo. Paste the first comment below within a minute of posting — that's where the real read happens.

## First comment

> [maintainer: if one of us has a real "I watched a key go out" moment, open with that instead — a true, specific story lands harder than the general version below. Don't invent one; the general opener is fine if nobody has the real thing.]

The thing that bugged me: when you let an AI coding agent work in a repo, you can't easily see what it ships upstream. It reads files to answer you, and some of those files have keys in them. If one of them is your `.env`, that key is now sitting in a request body on its way to a third party, and you'd never know unless you happened to be watching the wire.

So leakproof is a local proxy you put in front of the tool (`leakproof run -- claude`). It reads every outbound request, and redacts or blocks anything that looks like a secret before it leaves your machine. Same scanner also ships as a pre-commit hook if you'd rather catch it at the git boundary instead.

It runs local for a boring structural reason, not an ideological one: a hosted secret scanner has to receive your secret in order to scan it, which defeats the point. Regex and entropy handle the known key formats with no model at all. There's an optional second pass through a small local model (qwen2.5 1.5B on ollama). Keyword scanners like gitleaks mostly decide by the variable name around a value; the local pass reads the value, so it catches a live database URL or a customer's email sitting in a fixture even when nothing's named like a secret.

What it doesn't do yet, so nobody's surprised: it wraps CLI tools that respect a base-URL env var, which today means Claude Code and aider. GUI editors like Cursor talk to their own backend and need a real proxy plus a cert; that's the next job, not this one. It's a day old and several of us built it in parallel, so there are rough edges. The semantic layer is a 1.5B model, so it'll miss things and sometimes cry wolf; the regex layer is the part you can lean on.

MIT, free for a single developer, no account. The money plan is a team tier: one shared redaction policy, a central audit log instead of a file per laptop, and a CI gate that fails a build when a secret would've shipped. That last one is the piece a security lead at a regulated shop can't get from anything cloud-based, which is the whole reason we think there's a business here.

What I'd actually like back from you: which AI tool we should wrap next, and your worst false-positive story from gitleaks or trufflehog so we can throw it at the scanner.

## Launch checklist

Build and staging steps are go-now (local, reversible). Anything marked GATED waits on Armani's own word.

- [ ] product runs end-to-end: `leakproof run -- claude` actually redacts a planted key (the demo passes for real, not in theory)
- [ ] name locked; pypi + npm + domain claimed under the final name
- [ ] README + landing final, matched to the real CLI output (no invented terminal lines)
- [ ] demo GIF recorded from the real tool (see DEMO.md)
- [ ] first comment proofread, pasted into a scratch doc ready to drop
- [ ] pick a slot: a US-morning weekday (roughly 8–10am Eastern) gets the most eyes; avoid Friday/weekend
- [GATED] confirm the hamstudios GitHub + an HN account are set up (Armani's direct go)
- [GATED] flip the repo public under hamstudios
- [GATED] submit the Show HN, then paste the first comment immediately
- [ ] for the first few hours: answer every comment fast, don't argue, log the feature requests

One more, learned the hard way by other Show HN posts: don't ask friends to upvote in a burst. HN's flamew/voting-ring detection will bury the post and it doesn't come back. Let it ride on its own.
