# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Who makes this software, and the notices every copy and every report keeps.

All user-facing names and notices come from here: the CLI, every report format,
the HTTP User-Agent, and the package metadata. The LICENSE and NOTICE files say
these notices must stay. CI fails when they are removed (src/scripts/check_licensing.py).
"""

from __future__ import annotations

PRODUCT_NAME = "Aevrin MCP Scanner"
PRODUCT_ID = "aevrin-mcp-scanner"  # in license keys, the User-Agent, and package metadata
VENDOR = "Aevrin"
COPYRIGHT = "Copyright (c) 2026 Aevrin"

LICENSE_ID = "PolyForm-Noncommercial-1.0.0"  # SPDX identifier
LICENSE_NAME = "PolyForm Noncommercial License 1.0.0"
LICENSE_URL = "https://polyformproject.org/licenses/noncommercial/1.0.0"

# Shown when no valid commercial license is active. Noncommercial use needs no key.
NONCOMMERCIAL_NOTICE = (
    "Licensed for noncommercial use only (PolyForm Noncommercial 1.0.0). "
    "Commercial use requires a commercial license from Aevrin."
)


def attribution(version: str) -> str:
    """One line for the end of the CLI help and every report."""
    return f"{PRODUCT_NAME} {version}. {COPYRIGHT}."
