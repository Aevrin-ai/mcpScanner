# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Online activation, for licenses that ask for it ("online": true). Offline licenses never call out.

    scanner                                   Aevrin license server
       |  POST <activation>/v1/activations        |
       |  {license key, installation id, version} |
       | ---------------------------------------> |  checks the key, the seat count, revocation
       |  {receipt}  (signed, valid ~30 days)      |
       | <--------------------------------------- |

The receipt is a signed token of type "activation" naming the license and this
installation. It is saved and checked offline on every run. It is renewed when it has
less than a week left. When the server cannot be reached, the license keeps working
for `grace_days` after the receipt ends, and reports say so.

Only three things are sent: the license key, the installation id, and the scanner
version. Nothing about scans, targets, or findings. There is no other telemetry.

The installation id is a random UUID made on first use. It is not derived from the
machine, the user, or the network. In containers, set AEVRIN_INSTALLATION_ID to a
stable UUID per deployment (see docs/licensing.md).
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

import httpx

from mcp_scanner.branding import PRODUCT_ID
from mcp_scanner.licensing.crypto import TokenError, verify_token
from mcp_scanner.licensing.license import License, LicenseCheck, state_dir

INSTALLATION_FILE = "installation.json"
RECEIPT_FILE = "activation.json"
CLOCK_FILE = "clock.json"
RENEW_BEFORE_SECONDS = 7 * 86400
REQUEST_TIMEOUT = 10.0
DAY = 86400


class ActivationError(Exception):
    def __init__(self, message: str, revoked: bool = False) -> None:
        super().__init__(message)
        self.revoked = revoked


def _read(name: str) -> dict[str, Any]:
    try:
        data = json.loads((state_dir() / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(name: str, data: dict[str, Any]) -> None:
    folder = state_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(json.dumps(data, indent=1), encoding="utf-8")


def installation_id() -> str:
    """A random id for this installation, made once and then reused."""
    configured = os.environ.get("AEVRIN_INSTALLATION_ID", "").strip()
    if configured:
        return str(uuid.UUID(configured))  # raises ValueError for anything that is not a UUID
    saved = _read(INSTALLATION_FILE).get("id")
    try:
        return str(uuid.UUID(str(saved)))
    except ValueError:
        new = str(uuid.uuid4())
        _write(INSTALLATION_FILE, {"id": new, "created": int(time.time())})
        return new


def clock_went_back(now: float) -> bool:
    """True when the clock is more than a day behind the latest time seen. Records the time."""
    seen = _read(CLOCK_FILE).get("latest")
    latest = seen if isinstance(seen, int | float) else 0
    if now + DAY < latest:
        return True
    if now > latest:
        try:
            _write(CLOCK_FILE, {"latest": int(now)})
        except OSError:
            pass
    return False


def saved_receipt(lic: License, iid: str) -> dict[str, Any] | None:
    """The saved receipt, only if its signature is valid and it is for this license and installation."""
    token = _read(RECEIPT_FILE).get("receipt")
    if not isinstance(token, str):
        return None
    try:
        payload = verify_token(token, purpose="activation", typ="activation")
    except TokenError:
        return None  # an edited receipt is ignored, as if there were none
    if payload.get("lid") != lic.lid or payload.get("iid") != iid or not isinstance(payload.get("exp"), int):
        return None
    return payload


def request_receipt(lic: License, token: str, iid: str, version: str, client: httpx.Client | None = None) -> str:
    """Ask the license server for a receipt. Raises ActivationError."""
    assert lic.activation_url
    url = lic.activation_url.rstrip("/") + "/v1/activations"
    body = {"license": token, "installation_id": iid, "product": PRODUCT_ID, "version": version}
    own = client is None
    http = client or httpx.Client(timeout=REQUEST_TIMEOUT)
    try:
        response = http.post(url, json=body)
    except httpx.HTTPError as exc:
        raise ActivationError(f"could not reach the license server ({type(exc).__name__})") from exc
    finally:
        if own:
            http.close()
    try:
        data = response.json()
    except ValueError:
        data = {}
    message = str(data.get("error") or f"HTTP {response.status_code}")[:200]
    if response.status_code == 410:
        raise ActivationError(f"the license was revoked: {message}", revoked=True)
    if response.status_code != 200 or not isinstance(data.get("receipt"), str):
        raise ActivationError(f"the license server refused activation: {message}")
    return data["receipt"]


def save_receipt(receipt: str, lic: License, iid: str) -> dict[str, Any]:
    """Check a receipt from the server, then keep it. Raises ActivationError if it is not valid."""
    try:
        payload = verify_token(receipt, purpose="activation", typ="activation")
    except TokenError as exc:
        raise ActivationError(f"the server's receipt is not valid: {exc}") from exc
    if payload.get("lid") != lic.lid or payload.get("iid") != iid:
        raise ActivationError("the server's receipt is for another license or installation")
    _write(RECEIPT_FILE, {"receipt": receipt})
    return payload


def forget_receipt() -> None:
    (state_dir() / RECEIPT_FILE).unlink(missing_ok=True)


def apply(check: LicenseCheck, token: str, version: str, now: float, network: bool) -> LicenseCheck:
    """Add the online part to an offline check: renew the receipt when needed, then judge it."""
    lic = check.license
    if check.state != "valid" or lic is None or not lic.online:
        return check
    iid = installation_id()
    receipt = saved_receipt(lic, iid)
    if network and (receipt is None or receipt["exp"] - now < RENEW_BEFORE_SECONDS):
        try:
            receipt = save_receipt(request_receipt(lic, token, iid, version), lic, iid)
        except ActivationError as exc:
            if exc.revoked:
                forget_receipt()
                return LicenseCheck("revoked", lic, str(exc), check.source)
            check.notes.append(str(exc))
    if receipt is not None and now < receipt["exp"]:
        return check
    if receipt is not None and now < receipt["exp"] + lic.grace_days * DAY:
        until = time.strftime("%Y-%m-%d", time.gmtime(receipt["exp"] + lic.grace_days * DAY))
        return LicenseCheck(
            "grace", lic, f"the license server was not reached; grace period until {until}", check.source, check.notes
        )
    # Keep the server's answer (for example "seat limit reached"), so the user knows why.
    return LicenseCheck(
        "activation-required",
        lic,
        "this online license is not activated on this installation",
        check.source,
        check.notes,
    )
