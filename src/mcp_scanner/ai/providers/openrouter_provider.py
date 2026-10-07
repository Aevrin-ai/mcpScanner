# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""OpenRouter, through the official `openai` SDK pointed at OpenRouter's API.

OpenRouter gives one key for models from many companies. Model names include the
company, for example "anthropic/claude-sonnet-5.5" or "openai/gpt-5-mini".
OpenRouter reports the real cost of each call, so no price table is needed.
"""

from __future__ import annotations

from typing import Any

from mcp_scanner import PRODUCT_NAME
from mcp_scanner.ai.providers.base import AIProvider, AIResponse
from mcp_scanner.config.settings import AISettings
from mcp_scanner.core.errors import AIProviderError

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


class OpenRouterProvider(AIProvider):
    name = "openrouter"
    api_key_env = "OPENROUTER_API_KEY"
    default_model = "anthropic/claude-sonnet-5.5"
    install_extra = "openrouter"

    def __init__(self, settings: AISettings, api_key: str | None = None) -> None:
        super().__init__(settings, api_key)
        try:
            import openai
        except ImportError as exc:
            raise self.missing_sdk(exc) from exc
        self._openai = openai
        self._client = openai.OpenAI(
            api_key=self._api_key,
            base_url=OPENROUTER_BASE_URL,
            timeout=settings.timeout,
            max_retries=settings.max_retries,
        )

    def complete(self, system: str, user: str) -> AIResponse:
        try:
            response: Any = self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                max_tokens=self.settings.max_output_tokens,
                extra_headers={"X-OpenRouter-Title": PRODUCT_NAME},
            )
        except self._openai.OpenAIError as exc:
            raise AIProviderError(f"OpenRouter request failed: {type(exc).__name__}: {str(exc)[:300]}") from exc
        choices = getattr(response, "choices", None) or []
        if not choices:
            # OpenRouter sends errors from the model provider inside a normal looking answer.
            error = getattr(response, "error", None) or getattr(response, "model_extra", {}).get("error")
            raise AIProviderError(f"OpenRouter returned no answer: {str(error)[:300]}")
        text = getattr(choices[0].message, "content", None) or ""
        usage = getattr(response, "usage", None)
        cost = getattr(usage, "cost", None)
        if cost is None and usage is not None:
            cost = (getattr(usage, "model_extra", None) or {}).get("cost")
        return AIResponse(
            text=text,
            input_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
            cost_usd=float(cost) if isinstance(cost, int | float) else None,
        )
