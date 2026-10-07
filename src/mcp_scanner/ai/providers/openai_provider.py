# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""OpenAI, through the official `openai` SDK and the Responses API."""

from __future__ import annotations

from typing import Any

from mcp_scanner.ai.providers.base import AIProvider, AIResponse
from mcp_scanner.config.settings import AISettings
from mcp_scanner.core.errors import AIProviderError


class OpenAIProvider(AIProvider):
    name = "openai"
    api_key_env = "OPENAI_API_KEY"
    default_model = "gpt-5.5"
    install_extra = "openai"

    def __init__(self, settings: AISettings, api_key: str | None = None) -> None:
        super().__init__(settings, api_key)
        try:
            import openai
        except ImportError as exc:
            raise self.missing_sdk(exc) from exc
        self._openai = openai
        self._client = openai.OpenAI(api_key=self._api_key, timeout=settings.timeout, max_retries=settings.max_retries)

    def complete(self, system: str, user: str) -> AIResponse:
        try:
            response: Any = self._client.responses.create(
                model=self.model,
                instructions=system,
                input=user,
                max_output_tokens=self.settings.max_output_tokens,
            )
        except self._openai.OpenAIError as exc:
            raise AIProviderError(f"OpenAI request failed: {type(exc).__name__}: {str(exc)[:300]}") from exc
        usage = getattr(response, "usage", None)
        return AIResponse(
            text=getattr(response, "output_text", "") or "",
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
        )
