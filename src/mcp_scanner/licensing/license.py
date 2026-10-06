# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""License keys: where the scanner finds one, and what a valid one allows. All offline.

A license key is a signed token (crypto.py) of type "license". Its payload:

    lid          license id, for example "L-2026-0042"
    licensee     the organization it is issued to
    edition      "commercial" (production), "development" (non-production), "evaluation" (trial)
    features     entitlements, for example ["scan", "ai", "reports"], or ["*"] for everything
    seats        how many installations may activate (online licenses), or null
    iat, nbf     issued at, valid from (Unix seconds)
    exp          expires at (Unix seconds), or null for a perpetual license
    max_major    the newest major version it covers, for example 1 for every 1.x release
    online       true when installations must activate with the license server
    activation   the server URL for online activation (signed, so it cannot be redirected)
    grace_days   how long an online license keeps working when the server cannot be reached

Without a key the scanner runs under the noncommercial terms of the LICENSE file and says so.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_scanner.branding import PRODUCT_ID
from mcp_scanner.licensing.crypto import TokenError, verify_token

EDITIONS = ("commercial", "development", "evaluation")
CLOCK_SKEW_SECONDS = 300
LICENSE_FILE = "license.lic"

# What a check can conclude. Only "valid" and "grace" count as licensed.
STATES = (
    "none",  # no key found: noncommercial terms
    "valid",
    "grace",  # online license, server not reached lately, still inside the grace period
    "expired",
    "not-yet-valid",
    "wrong-product",
    "wrong-version",
    "invalid",  # bad signature, unknown key, or malformed
    "activation-required",
    "revoked",
    "clock",  # the system clock went back in time
)


@dataclass(frozen=True)
class License:
    lid: str
    licensee: str
    edition: str
    features: tuple[str, ...]
    seats: int | None
    issued_at: int
    not_before: int
    expires_at: int | None
    max_major: int | None
    online: bool
    activation_url: str | None
    grace_days: int
    kid: str

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> License:
        def number(name: str, required: bool = False) -> int | None:
            value = data.get(name)
            if value is None and not required:
                return None
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise TokenError(f"license field {name!r} must be a whole number")
            return value

        lid, licensee, edition = data.get("lid"), data.get("licensee"), data.get("edition")
        if not isinstance(lid, str) or not lid or not isinstance(licensee, str) or not licensee:
            raise TokenError("license has no id or licensee")
        if edition not in EDITIONS:
            raise TokenError(f"unknown license edition {edition!r}")
        features = data.get("features") or []
        if not isinstance(features, list) or not all(isinstance(f, str) for f in features):
            raise TokenError("license features must be a list of names")
        url = data.get("activation")
        # https only. Plain http is accepted for this machine alone, to test a local license server.
        secure = isinstance(url, str) and url.startswith(("https://", "http://127.0.0.1:", "http://localhost:"))
        if data.get("online") is True and not secure:
            raise TokenError("an online license needs an https activation URL")
        issued = number("iat", required=True) or 0
        return cls(
            lid=lid[:100],
            licensee=licensee[:200],
            edition=edition,
            features=tuple(features),
            seats=number("seats"),
            issued_at=issued,
            not_before=number("nbf") or issued,
            expires_at=number("exp"),
            max_major=number("max_major"),
            online=data.get("online") is True,
            activation_url=url if isinstance(url, str) else None,
            grace_days=number("grace_days") or 14,
            kid=str(data.get("kid")),
        )

    def allows(self, feature: str) -> bool:
        return "*" in self.features or feature in self.features


@dataclass
class LicenseCheck:
    state: str
    license: License | None = None
    reason: str = ""
    source: str = ""  # where the key came from: a variable name or a file path, never the key
    notes: list[str] = field(default_factory=list)

    @property
    def licensed(self) -> bool:
        return self.state in ("valid", "grace") and self.license is not None


def state_dir() -> Path:
    """Where the license, installation id, and activation receipt are kept."""
    custom = os.environ.get("AEVRIN_STATE_DIR")
    return Path(custom).expanduser() if custom else Path.home() / ".aevrin-mcp-scanner"


def find_license_token() -> tuple[str, str] | None:
    """(key, where it came from). Order: AEVRIN_LICENSE, AEVRIN_LICENSE_FILE, the saved license file."""
    inline = os.environ.get("AEVRIN_LICENSE", "").strip()
    if inline:
        return inline, "AEVRIN_LICENSE"
    for path in (os.environ.get("AEVRIN_LICENSE_FILE", ""), str(state_dir() / LICENSE_FILE)):
        if not path:
            continue
        file = Path(path).expanduser()
        try:
            text = file.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text:
            return text, str(file)
    return None


def major(version: str) -> int:
    try:
        return int(version.split(".", 1)[0])
    except ValueError:
        return 0


def check_token(token: str, version: str, now: float | None = None, source: str = "") -> LicenseCheck:
    """Everything that can be checked offline: signature, product, dates, and version."""
    now = time.time() if now is None else now
    try:
        payload = verify_token(token, purpose="license", typ="license")
        lic = License.from_payload(payload)
    except TokenError as exc:
        return LicenseCheck("invalid", reason=f"the license key is not valid: {exc}", source=source)
    if payload.get("product") != PRODUCT_ID:
        return LicenseCheck("wrong-product", lic, f"this license is for {payload.get('product')!r}", source)
    if now + CLOCK_SKEW_SECONDS < lic.not_before:
        return LicenseCheck("not-yet-valid", lic, f"valid from {_date(lic.not_before)}", source)
    if lic.expires_at is not None and now - CLOCK_SKEW_SECONDS > lic.expires_at:
        return LicenseCheck("expired", lic, f"expired on {_date(lic.expires_at)}", source)
    if lic.max_major is not None and major(version) > lic.max_major:
        return LicenseCheck("wrong-version", lic, f"covers versions up to {lic.max_major}.x, this is {version}", source)
    return LicenseCheck("valid", lic, source=source)


def _date(timestamp: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(timestamp))
