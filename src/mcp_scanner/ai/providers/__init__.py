# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""AI providers. Add one by writing an AIProvider subclass and adding it to PROVIDERS."""

from __future__ import annotations

from mcp_scanner.ai.providers.anthropic_provider import AnthropicProvider
from mcp_scanner.ai.providers.base import AIProvider, AIResponse
from mcp_scanner.ai.providers.groq_provider import GroqProvider
from mcp_scanner.ai.providers.openai_provider import OpenAIProvider
from mcp_scanner.ai.providers.openrouter_provider import OpenRouterProvider
from mcp_scanner.ai.providers.xai_provider import XAIProvider
from mcp_scanner.config.settings import AISettings
from mcp_scanner.core.errors import AIProviderError

PROVIDERS: dict[str, type[AIProvider]] = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "xai": XAIProvider,
    "openrouter": OpenRouterProvider,
    "groq": GroqProvider,
}

__all__ = ["PROVIDERS", "AIProvider", "AIResponse", "create_provider"]


def create_provider(settings: AISettings) -> AIProvider:
    if not settings.provider:
        raise AIProviderError(
            "No AI provider chosen. Use --ai-provider openai|anthropic|xai|openrouter|groq or set ai.provider."
        )
    cls = PROVIDERS.get(settings.provider)
    if cls is None:
        raise AIProviderError(f"Unknown AI provider '{settings.provider}'. Use one of: {', '.join(PROVIDERS)}")
    return cls(settings)
