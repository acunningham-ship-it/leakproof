# landing/

Public landing page for leakproof (single-file, zero-build static site).

- `index.html` — the page. Deploy anywhere (GitHub Pages / `tailscale serve` / Netlify).
  Demo + numbers are grounded in the real scanner output (rules-only, deterministic),
  not invented. Repoint copy via the marked block at the top of the file.
- `gitleaks-evidence.txt` — reproducible receipt backing the "gitleaks 0 → leakproof 3"
  side-by-side claim (gitleaks v8.30.1 vs scanner lane/semantic, rules-only).

⚠️ PUBLISH GATE: this page is NOT deployed. Nothing public — no deploy, no funnel —
until Armani's direct go. Recording the demo GIF is done with semantic OFF
(LEAKPROOF_SEMANTIC=0) per the rules-only-for-v1 decision.
