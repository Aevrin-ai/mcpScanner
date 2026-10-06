# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""The interface every AI provider follows.

A provider turns (system text, user text) into an answer. That is all.
Prompt building, redaction, budgets, and parsing live in `ai/review.py`.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass

from mcp_scanner.config.settings import AISettings
from mcp_scanner.core.errors import AIProviderError


@dataclass
class AIResponse:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    # Set when the provider reports the real price of the call (OpenRouter does).
    cost_usd: float | None = None


class AIProvider(ABC):
    name: str = ""
    api_key_env: str = ""
    default_model: str = ""
    install_extra: str = ""

    def __init__(self, settings: AISettings, api_key: str | None = None) -> None:
        self.settings = settings
        self.model = settings.model or self.default_model
        key = api_key or os.environ.get(self.api_key_env, "")
        if not key:
            raise AIProviderError(f"{self.api_key_env} is not set. Add it to your environment or .env file.")
        self._api_key = key

    @abstractmethod
    def complete(self, system: str, user: str) -> AIResponse:
        """Send one request. Raise AIProviderError on any failure."""

    def missing_sdk(self, exc: ImportError) -> AIProviderError:
        return AIProviderError(
            f"The {self.name} SDK is not installed. Run: pip install 'aevrin-mcp-scanner[{self.install_extra}]' ({exc.name})"
        )

    def __repr__(self) -> str:
        # Never show the key.
        return f"{type(self).__name__}(model={self.model!r})"
