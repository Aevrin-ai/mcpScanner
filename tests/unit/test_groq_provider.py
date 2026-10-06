from types import SimpleNamespace
from typing import Any

import pytest

from mcp_scanner.ai.providers import create_provider
from mcp_scanner.ai.providers.groq_provider import GROQ_BASE_URL, REASONING_ROOM, GroqProvider
from mcp_scanner.config.settings import AISettings
from mcp_scanner.core.errors import AIProviderError


class FakeCompletions:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.kwargs: dict[str, Any] = {}

    def create(self, **kwargs: Any) -> Any:
        self.kwargs = kwargs
        return self.response


def provider_with(
    response: Any, monkeypatch: pytest.MonkeyPatch, model: str | None = None
) -> tuple[GroqProvider, FakeCompletions]:
    monkeypatch.setenv("GROQ_API_KEY", "test-key-not-real")
    provider = GroqProvider(AISettings(enabled=True, provider="groq", model=model, max_output_tokens=500))
    fake = FakeCompletions(response)
    provider._client = SimpleNamespace(chat=SimpleNamespace(completions=fake))  # type: ignore[assignment]
    return provider, fake


def answer(content: str, finish: str = "stop") -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content), finish_reason=finish)],
        usage=SimpleNamespace(prompt_tokens=200, completion_tokens=40),
    )


def test_groq_uses_its_base_url_and_default_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "test-key-not-real")
    provider = create_provider(AISettings(enabled=True, provider="groq"))
    assert isinstance(provider, GroqProvider)
    assert str(provider._client.base_url).rstrip("/") == GROQ_BASE_URL
    assert provider.model == "openai/gpt-oss-120b"
    assert "test-key" not in repr(provider)


def test_groq_reasoning_model_gets_low_effort_and_room(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, fake = provider_with(answer('{"summary": "ok"}'), monkeypatch)
    result = provider.complete("system text", "user text")
    assert result.text == '{"summary": "ok"}' and (result.input_tokens, result.output_tokens) == (200, 40)
    assert result.cost_usd is None
    assert fake.kwargs["max_completion_tokens"] == 500 + REASONING_ROOM
    assert fake.kwargs["extra_body"] == {"reasoning_effort": "low", "include_reasoning": False}


def test_groq_other_models_get_plain_options(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, fake = provider_with(answer("{}"), monkeypatch, model="qwen/qwen3.8-27b")
    provider.complete("s", "u")
    assert fake.kwargs["max_completion_tokens"] == 500 and "extra_body" not in fake.kwargs


def test_groq_cut_off_answer_is_a_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, _ = provider_with(answer("", finish="length"), monkeypatch)
    with pytest.raises(AIProviderError, match="max_output_tokens"):
        provider.complete("s", "u")


def test_groq_missing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(AIProviderError, match="GROQ_API_KEY is not set"):
        create_provider(AISettings(enabled=True, provider="groq"))


class TooLargeOnce(FakeCompletions):
    """Answers the first request with Groq's "request too large" error."""

    def __init__(self, response: Any, requested: int) -> None:
        super().__init__(response)
        self.requested = requested
        self.rooms: list[int] = []

    def create(self, **kwargs: Any) -> Any:
        import httpx
        import openai

        self.rooms.append(kwargs["max_completion_tokens"])
        if len(self.rooms) == 1:
            response = httpx.Response(
                413, request=httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
            )
            message = f"Request too large on tokens per minute (TPM): Limit 8000, Requested {self.requested}"
            raise openai.APIStatusError(message, response=response, body=None)
        return self.response


def test_groq_shrinks_the_answer_room_when_too_large(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, _ = provider_with(answer("{}"), monkeypatch)
    fake = TooLargeOnce(answer('{"ok": true}'), requested=8200)
    provider._client = SimpleNamespace(chat=SimpleNamespace(completions=fake))  # type: ignore[assignment]
    assert provider.complete("s", "u").text == '{"ok": true}'
    first = 500 + REASONING_ROOM
    assert fake.rooms == [first, first - 200 - 100]


def test_groq_gives_a_clear_error_when_the_prompt_alone_is_too_large(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, _ = provider_with(answer("{}"), monkeypatch)
    fake = TooLargeOnce(answer("{}"), requested=20000)
    provider._client = SimpleNamespace(chat=SimpleNamespace(completions=fake))  # type: ignore[assignment]
    with pytest.raises(AIProviderError, match="max_input_chars"):
        provider.complete("s", "u")
    assert len(fake.rooms) == 1
