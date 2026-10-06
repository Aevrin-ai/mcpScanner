# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Make untrusted server text safe to send to an AI model.

1. Secrets are replaced with markers, so they never leave this machine.
2. Text is cut to a size limit.
3. Text is wrapped in random markers. The model is told that anything between
   the markers is data, never instructions. Because the markers are random for
   every call, a server cannot fake the closing marker in advance.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from mcp_scanner.utils.secrets import redact


def clean(text: str, limit: int, extra_secrets: list[str] | None = None) -> str:
    result = redact(text)
    for value in extra_secrets or []:
        if value:
            result = result.replace(value, "[REDACTED canary]")
    if len(result) > limit:
        result = result[:limit] + f"...(cut, {len(result) - limit} more characters)"
    return result


@dataclass
class Fence:
    """Random markers for one AI call."""

    token: str = field(default_factory=lambda: secrets.token_hex(8))

    @property
    def start(self) -> str:
        return f"<<<UNTRUSTED_DATA_{self.token}>>>"

    @property
    def end(self) -> str:
        return f"<<<END_UNTRUSTED_DATA_{self.token}>>>"

    def wrap(self, text: str) -> str:
        # The token is random, but remove any copy anyway, so the data can never close the fence.
        safe = text.replace(self.token, "[token]")
        return f"{self.start}\n{safe}\n{self.end}"
