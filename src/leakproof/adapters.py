"""leakproof L4 — tool adapters.

`leakproof run -- <tool> [args...]` launches an AI coding tool with its API
traffic pointed at the local leakproof proxy, so every outbound request passes
through the secret/PII scanner before it can leave the machine.

The interception trick is the same one leanroom used in front of Claude Code:
override the tool's API base URL via environment to a localhost address. No CA
install, no system proxy, no root — it just works for tools that honor a
base-URL env var (Claude Code, aider, and anything on the OpenAI/Anthropic
SDKs). GUI editors (Cursor/Copilot) need a real system proxy + CA and are
post-MVP.

Public API (the seam cli.py builds against):
    recipe_for(tool)            -> dict[str, str]   env overrides for a tool
    build_env(tool, proxy_url, base_env=None) -> dict[str, str]   full child env
    resolve_tool(argv)          -> (tool_key, command)            normalize argv
    run(tool, argv, proxy_url, base_env=None) -> int             exec, exit code

Stdlib only — no third-party deps.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Callable


# --- recipes -----------------------------------------------------------------
#
# A recipe maps a tool to the set of env vars that redirect its API traffic to
# `proxy_url`. Values are templates: the literal string "{proxy}" is replaced
# with the proxy URL at build time. Keeping them as templates (not closures)
# means the registry is plain data and trivially testable.

Recipe = dict[str, str]

# Routing follows opus-5's locked L1 proxy contract (#369): ONE proxy on
# 127.0.0.1:8747 with path-prefix upstreams — `/anthropic`→api.anthropic.com,
# `/openai`→api.openai.com. So a recipe value is "{proxy}<prefix>"; build_env
# substitutes "{proxy}" with the proxy base URL cli.py passes in.
_RECIPES: dict[str, Recipe] = {
    # Claude Code / the `claude` CLI — proven via leanroom's ANTHROPIC_BASE_URL.
    "claude": {
        "ANTHROPIC_BASE_URL": "{proxy}/anthropic",
    },
    # aider routes through litellm, which honors these base-URL vars. It may
    # target either provider, so we point both prefixes at the proxy.
    #
    # /v1 asymmetry (matches the proxy's verbatim path-forwarding): the OpenAI
    # SDK/litellm treat the base URL as the *versioned* root and append only
    # "/chat/completions", so the base must carry "/v1" → "{proxy}/openai/v1".
    # The Anthropic SDK treats its base as UNversioned and appends
    # "/v1/messages" itself, so its base must NOT carry "/v1".
    "aider": {
        "OPENAI_API_BASE": "{proxy}/openai/v1",
        "OPENAI_BASE_URL": "{proxy}/openai/v1",
        "ANTHROPIC_API_BASE": "{proxy}/anthropic",
        "ANTHROPIC_BASE_URL": "{proxy}/anthropic",
    },
}

# Aliases so `leakproof run -- claude-code ...` and `leakproof run -- claude ...`
# resolve to the same recipe.
_ALIASES: dict[str, str] = {
    "claude-code": "claude",
    "claudecode": "claude",
    "cc": "claude",
}

# Generic fallback for any unknown tool: set every base-URL var we know (each
# behind its provider prefix) plus a raw HTTPS_PROXY hint at the proxy root.
# Best-effort — a tool that honors none of these simply won't be intercepted
# (we warn in cli.py, not here).
_GENERIC: Recipe = {
    "ANTHROPIC_BASE_URL": "{proxy}/anthropic",
    "ANTHROPIC_API_BASE": "{proxy}/anthropic",
    "OPENAI_BASE_URL": "{proxy}/openai/v1",
    "OPENAI_API_BASE": "{proxy}/openai/v1",
    "HTTPS_PROXY": "{proxy}",
    "https_proxy": "{proxy}",
}


def supported_tools() -> list[str]:
    """Tool keys with a first-class recipe (not counting the generic fallback)."""
    return sorted(_RECIPES)


def _canonical(tool: str) -> str:
    name = os.path.basename(tool).lower()
    return _ALIASES.get(name, name)


def recipe_for(tool: str) -> Recipe:
    """Return the raw (templated) env recipe for a tool, or the generic fallback.

    Templates still contain "{proxy}"; use build_env() to materialize them.
    """
    return dict(_RECIPES.get(_canonical(tool), _GENERIC))


def is_supported(tool: str) -> bool:
    return _canonical(tool) in _RECIPES


def build_env(tool: str, proxy_url: str, base_env: dict | None = None) -> dict:
    """Full environment for the child: base_env (default os.environ) + overrides.

    The proxy URL is validated loosely — it must look like an http(s) URL so we
    never silently point a tool at a garbage value and let traffic escape.
    """
    if not proxy_url.startswith(("http://", "https://")):
        raise ValueError(f"proxy_url must be an http(s) URL, got {proxy_url!r}")
    env = dict(os.environ if base_env is None else base_env)
    for key, template in recipe_for(tool).items():
        env[key] = template.replace("{proxy}", proxy_url)
    # Marker so the proxy/child can tell it's running under leakproof (handy for
    # the TUI and for avoiding accidental recursion).
    env["LEAKPROOF_ACTIVE"] = "1"
    return env


def resolve_tool(argv: list[str]) -> tuple[str, list[str]]:
    """Split `run` argv into (tool_key, command).

    argv is everything after `leakproof run --`, e.g. ["aider", "--model", "x"].
    Returns the canonical tool key and the command list to exec (unchanged argv).
    """
    if not argv:
        raise ValueError("no tool given: usage `leakproof run -- <tool> [args...]`")
    return _canonical(argv[0]), list(argv)


def run(
    tool: str,
    argv: list[str],
    proxy_url: str,
    base_env: dict | None = None,
    _spawn: Callable[..., int] | None = None,
) -> int:
    """Launch the tool with intercept env; return its exit code.

    `_spawn` is injectable for tests (defaults to a real subprocess). The tool
    binary must be on PATH; we fail loudly rather than launch the wrong thing.
    """
    env = build_env(tool, proxy_url, base_env)
    if shutil.which(argv[0]) is None:
        raise FileNotFoundError(f"{argv[0]!r} not found on PATH")
    spawn = _spawn or _default_spawn
    return spawn(argv, env)


def _default_spawn(argv: list[str], env: dict) -> int:
    proc = subprocess.run(argv, env=env)
    return proc.returncode
