# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Read JSON that may contain comments and trailing commas (JSONC).

Editors like VS Code allow comments in settings files. Plain json.loads fails on them.
"""

from __future__ import annotations

import json
import re
from typing import Any

_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def strip_comments(text: str) -> str:
    """Remove // and /* */ comments, but never touch text inside strings."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def loads(text: str) -> Any:
    """Parse JSON first. If that fails, try again without comments and trailing commas."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        cleaned = _TRAILING_COMMA.sub(r"\1", strip_comments(text))
        return json.loads(cleaned)
