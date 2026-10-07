# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Groq, through the official `openai` SDK pointed at Groq's OpenAI compatible API.

Groq runs open models very fast. The default, "openai/gpt-oss-120b", is a reasoning
model: it thinks before it answers, and those thinking tokens count against the
answer limit. So the scanner asks for low reasoning effort, leaves the thinking out
of the answer, and adds a little room for it on top of `ai.max_output_tokens`.

Groq checks each request against a tokens per minute limit (8,000 on the free tier),
and it counts the answer room you ask for, not only what is used. When a request is
too large, the answer room is shrunk to fit and the request is sent once more.

Groq does not report the price of a call. Set `ai.pricing` to see a cost.
"""

from __future__ import annotations

import re
from typing import Any

from mcp_scanner.ai.providers.base import AIProvider, AIResponse
from mcp_scanner.config.settings import AISettings
from mcp_scanner.core.errors import AIProviderError

GROQ_BASE_URL = "https://api.groq.com/openai/v1"
# Extra answer tokens for models that reason first. Low effort reasoning stays well below this.
REASONING_ROOM = 1000
# The smallest answer room worth a second try. Below it the JSON answer would be cut off.
MIN_ANSWER_ROOM = 800
_TOO_LARGE = re.compile(r"Limit (\d+), Requested (\d+)")


def is_reasoning_model(model: str) -> bool:
    return model.startswith("openai/gpt-oss")


class GroqProvider(AIProvider):
    name = "groq"
    api_key_env = "GROQ_API_KEY"
    default_model = "openai/gpt-oss-120b"
    install_extra = "groq"

    def __init__(self, settings: AISettings, api_key: str | None = None) -> None:
        super().__init__(settings, api_key)
        try:
            import openai
        except ImportError as exc:
            raise self.missing_sdk(exc) from exc
        self._openai = openai
        self._client = openai.OpenAI(
            api_key=self._api_key,
            base_url=GROQ_BASE_URL,
            timeout=settings.timeout,
            max_retries=settings.max_retries,
        )

    def complete(self, system: str, user: str) -> AIResponse:
        room = self.settings.max_output_tokens + (REASONING_ROOM if is_reasoning_model(self.model) else 0)
        try:
            response = self._send(system, user, room)
        except self._openai.APIStatusError as exc:
            smaller = _room_that_fits(exc, room)
            if smaller is None:
                raise _error(exc) from exc
            try:
                response = self._send(system, user, smaller)
            except self._openai.OpenAIError as again:
                raise _error(again) from again
        except self._openai.OpenAIError as exc:
            raise _error(exc) from exc
        choices = getattr(response, "choices", None) or []
        if not choices:
            raise AIProviderError("Groq returned no answer")
        text = getattr(choices[0].message, "content", None) or ""
        if not text and getattr(choices[0], "finish_reason", None) == "length":
            raise AIProviderError("Groq used the whole answer limit before answering. Raise ai.max_output_tokens.")
        usage = getattr(response, "usage", None)
        return AIResponse(
            text=text,
            input_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
        )

    def _send(self, system: str, user: str, room: int) -> Any:
        options: dict[str, Any] = {"max_completion_tokens": room}
        if is_reasoning_model(self.model):
            options["extra_body"] = {"reasoning_effort": "low", "include_reasoning": False}
        return self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            **options,
        )


def _room_that_fits(exc: Any, room: int) -> int | None:
    """For a "request too large" answer: an answer room that fits the limit, or None."""
    match = _TOO_LARGE.search(str(exc))
    if getattr(exc, "status_code", None) not in (413, 429) or match is None:
        return None
    limit, requested = int(match.group(1)), int(match.group(2))
    smaller = room - (requested - limit) - 100
    return smaller if MIN_ANSWER_ROOM <= smaller < room else None


def _error(exc: Exception) -> AIProviderError:
    text = str(exc)
    if _TOO_LARGE.search(text):
        return AIProviderError(
            "Groq refused the request: it is larger than your tokens per minute limit. Lower ai.max_input_chars "
            f"(for example to 12000) or use a paid Groq tier. ({text[:200]})"
        )
    return AIProviderError(f"Groq request failed: {type(exc).__name__}: {text[:300]}")
