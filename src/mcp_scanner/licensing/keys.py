# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Aevrin's public verification keys. Public keys only: they can check signatures, not make them.

Each key has one purpose:
  license     signs license keys (kept offline by Aevrin)
  release     signs the integrity manifest of each official release (kept in the CI secret store)
  activation  signs activation receipts (kept on the license server)

To rotate a key: make a new one with src/scripts/licensing/keygen.py, add its line here,
and keep the old line until every license or release it signed has expired.
To revoke a key: remove its line. Everything it signed stops being trusted.

Changing this file changes which signatures the scanner trusts, so it is a protected
file: CI fails unless the change is deliberate (src/scripts/protected-files.sha256).
"""

from __future__ import annotations

# kid -> (purpose, raw Ed25519 public key in base64url)
TRUSTED_KEYS: dict[str, tuple[str, str]] = {
    "license-2026-10": ("license", "opazNW7Row0ylBfYPw0kzOPHVOAifi2cJjOCgCXa7_8"),
    "release-2026-10": ("release", "a5hs00Ud7PIBFo3onCna4-nxFIMb1Hb9s67X-1JWS3o"),
    "activation-2026-10": ("activation", "Gj5Ifq9qdxCiWA_8s9km9qjxLQVqmPObkie7wixNNu0"),
}
