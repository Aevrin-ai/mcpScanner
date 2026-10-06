from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mcp_scanner.ai.providers import create_provider
from mcp_scanner.ai.providers.openrouter_provider import OPENROUTER_BASE_URL, OpenRouterProvider
from mcp_scanner.config.settings import AISettings, SandboxSettings
from mcp_scanner.core.errors import AIProviderError
from mcp_scanner.sandbox.canary import CanarySet
from mcp_scanner.sandbox.docker import build_docker_plan
from mcp_scanner.sandbox.workspace import CACHE_PREFIXES, Workspace


class FakeCompletions:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.kwargs: dict[str, Any] = {}

    def create(self, **kwargs: Any) -> Any:
        self.kwargs = kwargs
        return self.response


def provider_with(response: Any, monkeypatch: pytest.MonkeyPatch) -> tuple[OpenRouterProvider, FakeCompletions]:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key-not-real")
    provider = OpenRouterProvider(AISettings(enabled=True, provider="openrouter", max_output_tokens=321))
    fake = FakeCompletions(response)
    provider._client = SimpleNamespace(chat=SimpleNamespace(completions=fake))  # type: ignore[assignment]
    return provider, fake


def test_openrouter_uses_its_base_url_and_default_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key-not-real")
    provider = create_provider(AISettings(enabled=True, provider="openrouter"))
    assert isinstance(provider, OpenRouterProvider)
    assert str(provider._client.base_url).rstrip("/") == OPENROUTER_BASE_URL
    assert provider.model == "anthropic/claude-sonnet-5.5"
    assert "test-key" not in repr(provider)


def test_openrouter_reads_text_tokens_and_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content='{"summary": "ok"}'))],
        usage=SimpleNamespace(prompt_tokens=120, completion_tokens=30, cost=0.0021),
    )
    provider, fake = provider_with(response, monkeypatch)
    answer = provider.complete("system text", "user text")
    assert answer.text == '{"summary": "ok"}'
    assert (answer.input_tokens, answer.output_tokens, answer.cost_usd) == (120, 30, 0.0021)
    assert fake.kwargs["messages"][0] == {"role": "system", "content": "system text"}
    assert fake.kwargs["max_tokens"] == 321


def test_openrouter_empty_answer_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, _ = provider_with(SimpleNamespace(choices=[], usage=None, error={"message": "rate limited"}), monkeypatch)
    with pytest.raises(AIProviderError, match="no answer"):
        provider.complete("s", "u")


def test_openrouter_missing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(AIProviderError, match="OPENROUTER_API_KEY is not set"):
        create_provider(AISettings(enabled=True, provider="openrouter"))


def test_docker_plan_is_locked_down(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("mcp_scanner.sandbox.docker.shutil.which", lambda name: "docker")
    script = tmp_path / "server.py"
    script.write_text("print(1)", encoding="utf-8")
    ws = Workspace(CanarySet())
    try:
        plan = build_docker_plan("python", [str(script)], {"API_TOKEN": "secret-value"}, SandboxSettings(), ws)
    finally:
        ws.cleanup()
    argv = " ".join(plan.argv)
    for flag in (
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--user 65534:65534",
    ):
        assert flag in argv
    assert plan.image == SandboxSettings().docker_image_python
    assert "secret-value" not in argv  # env values travel through the CLI environment, not the process list
    assert plan.cli_env["API_TOKEN"] == "secret-value"
    assert any(m.endswith(":ro") for m in plan.mounts) and "/mnt/arg0/server.py" in argv


def test_package_caches_are_not_reported_as_written_files() -> None:
    ws = Workspace(CanarySet())
    try:
        (ws.home / ".npm" / "_cacache").mkdir(parents=True)
        (ws.home / ".npm" / "_cacache" / "blob").write_text("x", encoding="utf-8")
        (ws.home / ".bashrc").write_text("evil", encoding="utf-8")
        assert ws.changed_files(CACHE_PREFIXES) == ["home/.bashrc"]
    finally:
        ws.cleanup()
