# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Anthropic, through the official `anthropic` SDK and the Messages API."""

from __future__ import annotations

from typing import Any

from mcp_scanner.ai.providers.base import AIProvider, AIResponse
from mcp_scanner.config.settings import AISettings
from mcp_scanner.core.errors import AIProviderError


class AnthropicProvider(AIProvider):
    name = "anthropic"
    api_key_env = "ANTHROPIC_API_KEY"
    default_model = "claude-sonnet-5-5"
    install_extra = "anthropic"

    def __init__(self, settings: AISettings, api_key: str | None = None) -> None:
        super().__init__(settings, api_key)
        try:
            import anthropic
        except ImportError as exc:
            raise self.missing_sdk(exc) from exc
        self._anthropic = anthropic
        self._client = anthropic.Anthropic(
            api_key=self._api_key, timeout=settings.timeout, max_retries=settings.max_retries
        )

    def complete(self, system: str, user: str) -> AIResponse:
        try:
            response: Any = self._client.messages.create(
                model=self.model,
                max_tokens=self.settings.max_output_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except self._anthropic.AnthropicError as exc:
            raise AIProviderError(f"Anthropic request failed: {type(exc).__name__}: {str(exc)[:300]}") from exc
        text = "".join(getattr(block, "text", "") for block in response.content if getattr(block, "type", "") == "text")
        usage = getattr(response, "usage", None)
        return AIResponse(
            text=text,
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
        )
