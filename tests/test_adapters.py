"""Tests for leakproof.adapters (L4) — stdlib unittest, no deps, no network."""

import os
import unittest

from leakproof import adapters


PROXY = "http://127.0.0.1:8747"  # locked L1 proxy port (opus-5 #369)


class TestRecipes(unittest.TestCase):
    def test_claude_recipe_sets_anthropic_base_url(self):
        env = adapters.build_env("claude", PROXY, base_env={})
        self.assertEqual(env["ANTHROPIC_BASE_URL"], PROXY + "/anthropic")
        self.assertEqual(env["LEAKPROOF_ACTIVE"], "1")

    def test_claude_code_alias_resolves_to_claude(self):
        self.assertTrue(adapters.is_supported("claude-code"))
        self.assertEqual(
            adapters.recipe_for("claude-code"), adapters.recipe_for("claude")
        )

    def test_path_prefixed_tool_name_resolves(self):
        # `leakproof run -- /usr/local/bin/claude` should still match.
        env = adapters.build_env("/usr/local/bin/claude", PROXY, base_env={})
        self.assertEqual(env["ANTHROPIC_BASE_URL"], PROXY + "/anthropic")

    def test_aider_recipe_sets_litellm_base_urls(self):
        env = adapters.build_env("aider", PROXY, base_env={})
        # OpenAI base carries /v1 (SDK appends only /chat/completions); Anthropic
        # base does not (SDK appends /v1/messages itself).
        self.assertEqual(env["OPENAI_API_BASE"], PROXY + "/openai/v1")
        self.assertEqual(env["ANTHROPIC_BASE_URL"], PROXY + "/anthropic")

    def test_unknown_tool_uses_generic_fallback(self):
        self.assertFalse(adapters.is_supported("some-random-tool"))
        env = adapters.build_env("some-random-tool", PROXY, base_env={})
        self.assertEqual(env["HTTPS_PROXY"], PROXY)  # raw root, no prefix
        self.assertEqual(env["OPENAI_API_BASE"], PROXY + "/openai/v1")

    def test_supported_tools_listed(self):
        self.assertIn("claude", adapters.supported_tools())
        self.assertIn("aider", adapters.supported_tools())


class TestBuildEnv(unittest.TestCase):
    def test_base_env_is_preserved(self):
        env = adapters.build_env("claude", PROXY, base_env={"PATH": "/x", "FOO": "bar"})
        self.assertEqual(env["PATH"], "/x")
        self.assertEqual(env["FOO"], "bar")

    def test_defaults_to_os_environ(self):
        os.environ["LEAKPROOF_TEST_SENTINEL"] = "yes"
        try:
            env = adapters.build_env("claude", PROXY)
            self.assertEqual(env["LEAKPROOF_TEST_SENTINEL"], "yes")
        finally:
            del os.environ["LEAKPROOF_TEST_SENTINEL"]

    def test_rejects_non_http_proxy_url(self):
        with self.assertRaises(ValueError):
            adapters.build_env("claude", "127.0.0.1:8747", base_env={})


class TestResolveTool(unittest.TestCase):
    def test_resolve_splits_tool_and_command(self):
        key, cmd = adapters.resolve_tool(["aider", "--model", "gpt-4o"])
        self.assertEqual(key, "aider")
        self.assertEqual(cmd, ["aider", "--model", "gpt-4o"])

    def test_resolve_empty_argv_raises(self):
        with self.assertRaises(ValueError):
            adapters.resolve_tool([])


class TestRun(unittest.TestCase):
    def test_run_passes_env_and_argv_to_spawn(self):
        captured = {}

        def fake_spawn(argv, env):
            captured["argv"] = argv
            captured["env"] = env
            return 0

        code = adapters.run(
            "claude", ["sh", "-c", "true"], PROXY, base_env={}, _spawn=fake_spawn
        )
        self.assertEqual(code, 0)
        self.assertEqual(captured["argv"], ["sh", "-c", "true"])
        self.assertEqual(captured["env"]["ANTHROPIC_BASE_URL"], PROXY + "/anthropic")

    def test_run_missing_binary_raises(self):
        with self.assertRaises(FileNotFoundError):
            adapters.run(
                "claude",
                ["leakproof-no-such-binary-xyz"],
                PROXY,
                base_env={},
                _spawn=lambda a, e: 0,
            )

    def test_run_propagates_exit_code(self):
        code = adapters.run(
            "claude", ["sh"], PROXY, base_env={}, _spawn=lambda a, e: 42
        )
        self.assertEqual(code, 42)


if __name__ == "__main__":
    unittest.main()
