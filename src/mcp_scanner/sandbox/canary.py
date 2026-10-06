# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Canaries: fake secrets that should never come back out of a server.

We plant a random fake secret in the server environment and in decoy files.
If that value ever shows up in a tool result, prompt, or resource, the server
read something it should not have, and sent it back to the agent. That is proof,
not a guess.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

# This env name looks like a real secret on purpose. Code that steals secrets
# from the environment usually grabs everything that looks like a key or token.
CANARY_ENV_NAME = "SERVICE_API_TOKEN"


@dataclass
class CanarySet:
    """All canary values for one scan."""

    env_value: str = field(default_factory=lambda: "aevrin_canary_env_" + secrets.token_hex(12))
    file_value: str = field(default_factory=lambda: "aevrin_canary_file_" + secrets.token_hex(12))
    input_value: str = field(default_factory=lambda: "aevrin-canary-input-" + secrets.token_hex(6))

    def secret_values(self) -> list[str]:
        """Values that must never appear in server output."""
        return [self.env_value, self.file_value]

    def find_leaks(self, text: str) -> list[str]:
        return [value for value in self.secret_values() if value in text]


def decoy_files(canary: CanarySet) -> dict[str, str]:
    """Fake sensitive files to put in the fake home folder. Paths are relative to home."""
    key = canary.file_value
    return {
        ".ssh/id_rsa": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{key}\n-----END OPENSSH PRIVATE KEY-----\n",
        ".aws/credentials": f"[default]\naws_access_key_id = AKIA{key[-16:].upper()}\naws_secret_access_key = {key}\n",
        ".env": f"DATABASE_PASSWORD={key}\nAPI_KEY={key}\n",
        ".config/gh/hosts.yml": f"github.com:\n    oauth_token: {key}\n",
    }
