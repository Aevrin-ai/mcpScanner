# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Expand ${VAR} style placeholders in config values.

We pass the environment in as a dict. We never change os.environ, so this is safe
to use from many threads.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping

# Supports ${VAR}, ${env:VAR}, and ${VAR:-default}.
_PLACEHOLDER = re.compile(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class MissingVariableError(ValueError):
    pass


def expand_value(text: str, env: Mapping[str, str], *, strict: bool = False) -> str:
    """Replace placeholders with values from `env`.

    If a variable is missing and has no default, we keep the placeholder as is,
    unless `strict` is True, then we raise an error.
    """

    def replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        if name in env:
            return env[name]
        if default is not None:
            return default
        if strict:
            raise MissingVariableError(f"Environment variable '{name}' is not set")
        return match.group(0)

    return _PLACEHOLDER.sub(replace, text)


def expand_mapping(values: Mapping[str, str], env: Mapping[str, str] | None = None) -> dict[str, str]:
    source = os.environ if env is None else env
    return {key: expand_value(str(val), source) for key, val in values.items()}


def expand_list(values: list[str], env: Mapping[str, str] | None = None) -> list[str]:
    source = os.environ if env is None else env
    return [expand_value(str(val), source) for val in values]


def has_placeholder(text: str) -> bool:
    return bool(_PLACEHOLDER.search(text))
