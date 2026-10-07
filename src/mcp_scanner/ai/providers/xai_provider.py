# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""xAI (Grok), through the official `xai_sdk` package."""

from __future__ import annotations

from typing import Any

from mcp_scanner.ai.providers.base import AIProvider, AIResponse
from mcp_scanner.config.settings import AISettings
from mcp_scanner.core.errors import AIProviderError


class XAIProvider(AIProvider):
    name = "xai"
    api_key_env = "XAI_API_KEY"
    default_model = "grok-4.6"
    install_extra = "xai"

    def __init__(self, settings: AISettings, api_key: str | None = None) -> None:
        super().__init__(settings, api_key)
        try:
            from xai_sdk import Client
            from xai_sdk.chat import system, user
        except ImportError as exc:
            raise self.missing_sdk(exc) from exc
        self._system, self._user = system, user
        self._client = Client(api_key=self._api_key, timeout=settings.timeout)

    def complete(self, system: str, user: str) -> AIResponse:
        last_error: Exception | None = None
        # xai_sdk has no retry setting, so we retry here.
        for _ in range(self.settings.max_retries + 1):
            try:
                chat = self._client.chat.create(
                    model=self.model,
                    messages=[self._system(system), self._user(user)],
                    max_tokens=self.settings.max_output_tokens,
                )
                response: Any = chat.sample()
                break
            except Exception as exc:
                last_error = exc
        else:
            raise AIProviderError(f"xAI request failed: {type(last_error).__name__}: {str(last_error)[:300]}")
        usage = getattr(response, "usage", None)
        return AIResponse(
            text=getattr(response, "content", "") or "",
            input_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
        )
