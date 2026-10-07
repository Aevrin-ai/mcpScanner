# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Signed tokens: the one format used for license keys and activation receipts.

    AEVRIN1.<payload>.<signature>

- payload: base64url of a JSON object. It names its signing key ("kid") and its type ("typ").
- signature: base64url of an Ed25519 signature over the bytes "AEVRIN1." + payload.

Ed25519 is a modern signature scheme (RFC 8032): small keys, fast, and no settings to
get wrong. The scanner holds only public keys (keys.py). The private keys stay with
Aevrin: they are never in this repository, the package, or the Docker image.

A token cannot be edited: changing one character of the payload breaks the signature.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from mcp_scanner.licensing import keys

PREFIX = "AEVRIN1"
MAX_TOKEN_CHARS = 16_000


class TokenError(ValueError):
    """The token is malformed, signed by an unknown key, or its signature does not match."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise TokenError("bad base64") from exc


def canonical_json(value: Any) -> bytes:
    """One exact byte form for a JSON value, so signatures are reproducible."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def public_key(kid: str, purpose: str) -> Ed25519PublicKey:
    """The trusted public key `kid`, only if it is meant for `purpose`."""
    entry = keys.TRUSTED_KEYS.get(kid)
    if entry is None:
        raise TokenError(f"signed by an unknown key ({kid[:40]})")
    key_purpose, raw = entry
    if key_purpose != purpose:
        # A key for one job never vouches for another: a leaked activation server key
        # cannot be used to make license keys.
        raise TokenError(f"key {kid} is not trusted for {purpose}")
    return Ed25519PublicKey.from_public_bytes(unb64url(raw))


def verify_bytes(message: bytes, signature: bytes, kid: str, purpose: str) -> None:
    try:
        public_key(kid, purpose).verify(signature, message)
    except InvalidSignature as exc:
        raise TokenError("the signature does not match: the data was changed or not signed by Aevrin") from exc


def sign_token(payload: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    """Make a token. Only Aevrin's tools call this, with a private key they keep."""
    body = b64url(canonical_json(payload))
    signature = private_key.sign(f"{PREFIX}.{body}".encode("ascii"))
    return f"{PREFIX}.{body}.{b64url(signature)}"


def verify_token(token: str, purpose: str, typ: str) -> dict[str, Any]:
    """The payload of a token whose signature is valid and whose type is `typ`. Raises TokenError."""
    token = token.strip()
    if len(token) > MAX_TOKEN_CHARS:
        raise TokenError("too long")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise TokenError(f"not an {PREFIX} token")
    _, body, signature = parts
    try:
        payload = json.loads(unb64url(body))
    except (UnicodeDecodeError, ValueError) as exc:
        raise TokenError("unreadable payload") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("kid"), str):
        raise TokenError("payload has no signing key id")
    # The signature is checked before any other field is trusted.
    verify_bytes(f"{PREFIX}.{body}".encode("ascii"), unb64url(signature), payload["kid"], purpose)
    if payload.get("typ") != typ:
        raise TokenError(f"this is a {payload.get('typ')!r} token, not a {typ!r} token")
    return payload
