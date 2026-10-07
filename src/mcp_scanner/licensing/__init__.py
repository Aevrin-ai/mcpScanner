# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Licensing for Aevrin MCP Scanner: license keys, activation, and build integrity.

See docs/licensing.md for how it works and docs/licensing-threat-model.md for its limits.

    crypto.py      the signed token format (Ed25519)
    keys.py        Aevrin's public verification keys
    license.py     finding and checking a license key (offline)
    activation.py  online activation for licenses that ask for it
    integrity.py   is this copy an official, unchanged release?
    status.py      the result shown in the CLI and in reports
"""
