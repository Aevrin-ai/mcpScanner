# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""The license and build status of this copy, as shown in the CLI and in every report.

Policy (chosen by Aevrin): nothing is blocked without a license. The LICENSE allows
noncommercial use, so an unlicensed copy runs fully and every report says
"Licensed for noncommercial use only". A valid commercial license replaces that line
with who the copy is licensed to. A modified build is always named as such.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from mcp_scanner import __version__
from mcp_scanner.branding import COPYRIGHT, LICENSE_ID, NONCOMMERCIAL_NOTICE, PRODUCT_NAME, VENDOR
from mcp_scanner.licensing import activation
from mcp_scanner.licensing.integrity import BuildCheck, verify_build
from mcp_scanner.licensing.license import LicenseCheck, check_token, find_license_token
from mcp_scanner.models.result import ProductInfo


@dataclass
class ProductStatus:
    license: LicenseCheck
    build: BuildCheck


_CACHE: ProductStatus | None = None


def check_license(network: bool = True, now: float | None = None) -> LicenseCheck:
    now = time.time() if now is None else now
    found = find_license_token()
    if found is None:
        return LicenseCheck("none")
    token, source = found
    # Recorded on every run with a key, also after it expired, so setting the clock back later is noticed.
    went_back = activation.clock_went_back(now)
    check = check_token(token, __version__, now, source)
    lic = check.license
    # Expiry and receipts depend on the clock. A clock set back in time is not trusted.
    clock_matters = check.state == "valid" and lic is not None and (lic.expires_at is not None or lic.online)
    if clock_matters and went_back:
        return LicenseCheck("clock", lic, "the system clock is earlier than on a previous run", source)
    return activation.apply(check, token, __version__, now, network)


def current(refresh: bool = False, network: bool = True) -> ProductStatus:
    """The status for this process. Checked once, then reused."""
    global _CACHE
    if _CACHE is None or refresh:
        _CACHE = ProductStatus(check_license(network), verify_build(__version__))
    return _CACHE


def license_notice(check: LicenseCheck) -> str:
    lic = check.license
    if check.licensed and lic is not None:
        until = f", valid until {time.strftime('%Y-%m-%d', time.gmtime(lic.expires_at))}" if lic.expires_at else ""
        extra = f" ({check.reason})" if check.state == "grace" else ""
        return f"Licensed to {lic.licensee} ({lic.edition} license {lic.lid}{until}){extra}."
    if check.state == "none":
        return NONCOMMERCIAL_NOTICE
    return f"License problem: {check.reason}. Running under the noncommercial terms. {NONCOMMERCIAL_NOTICE}"


def build_notice(build: BuildCheck) -> str | None:
    if build.state == "modified":
        shown = ", ".join(build.changed[:5])
        return f"Modified build: not an official {VENDOR} release ({build.reason}{': ' + shown if shown else ''})."
    if build.state == "development":
        return "Development build: not an official release."
    return None


def product_info(status: ProductStatus | None = None) -> ProductInfo:
    status = status or current()
    lic = status.license.license if status.license.licensed else None
    return ProductInfo(
        name=PRODUCT_NAME,
        vendor=VENDOR,
        version=__version__,
        copyright=COPYRIGHT,
        license=LICENSE_ID,
        license_state=status.license.state,
        licensee=lic.licensee if lic else None,
        license_id=lic.lid if lic else None,
        license_notice=license_notice(status.license),
        build=status.build.state,
        build_notice=build_notice(status.build),
    )
