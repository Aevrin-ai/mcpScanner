# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""`mcp-scanner license ...`: show, activate, and remove a commercial license, and verify this build."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Annotated

import typer

from mcp_scanner import __version__
from mcp_scanner.branding import COPYRIGHT, LICENSE_NAME, PRODUCT_NAME
from mcp_scanner.cli.common import err, fail, out, print_json
from mcp_scanner.licensing import activation, status
from mcp_scanner.licensing.integrity import verify_build
from mcp_scanner.licensing.license import LICENSE_FILE, check_token, state_dir

app = typer.Typer(help="Show, activate, or remove a commercial license, and verify this build.", no_args_is_help=True)


def _date(timestamp: int | None) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(timestamp)) if timestamp else "never"


@app.command("status")
def license_status(
    offline: Annotated[bool, typer.Option("--offline", help="Do not contact the license server.")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show the license and build status of this copy."""
    current = status.current(refresh=True, network=not offline)
    info = status.product_info(current)
    lic = current.license.license
    if json_out:
        data = info.model_dump()
        data["installation_id"] = activation.installation_id()
        if lic is not None:
            data["license_details"] = {
                "edition": lic.edition,
                "features": list(lic.features),
                "seats": lic.seats,
                "expires": _date(lic.expires_at),
                "covers_up_to_major": lic.max_major,
                "online": lic.online,
            }
        print_json(data)
        return
    out.print(f"{PRODUCT_NAME} {__version__}. {COPYRIGHT}. Source license: {LICENSE_NAME}.")
    out.print(f"License:      {current.license.state}")
    out.print(f"              {info.license_notice}")
    if lic is not None:
        out.print(f"Licensee:     {lic.licensee} ({lic.edition}, {lic.lid})")
        out.print(f"Features:     {', '.join(lic.features) or 'none'}")
        out.print(f"Expires:      {_date(lic.expires_at)}")
        if lic.online:
            out.print(f"Activation:   online, {lic.seats or 'unlimited'} seat(s), grace {lic.grace_days} days")
    for note in current.license.notes:
        out.print(f"Note:         {note}", style="yellow")
    if current.license.source:
        out.print(f"Key from:     {current.license.source}")
    out.print(f"Install ID:   {activation.installation_id()}")
    out.print(f"Build:        {current.build.state}{' - ' + info.build_notice if info.build_notice else ''}")


@app.command("activate")
def activate(
    key: Annotated[str, typer.Argument(help="The license key (AEVRIN1....) or a path to a .lic file.")],
) -> None:
    """Check a license key, save it for this user, and activate it online if the license asks for it."""
    path = Path(key).expanduser()
    token = path.read_text(encoding="utf-8").strip() if path.is_file() else key.strip()
    check = check_token(token, __version__)
    if check.state != "valid" or check.license is None:
        fail(f"This license key cannot be used: {check.reason or check.state}")
    lic = check.license
    if lic.online:
        iid = activation.installation_id()
        try:
            activation.save_receipt(activation.request_receipt(lic, token, iid, __version__), lic, iid)
        except activation.ActivationError as exc:
            fail(f"Activation failed: {exc}")
    folder = state_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / LICENSE_FILE).write_text(token + "\n", encoding="utf-8")
    out.print(f"Activated: licensed to {lic.licensee} ({lic.edition} license {lic.lid}).")
    out.print(f"Saved to {folder / LICENSE_FILE}. Keep this file private.")


@app.command("deactivate")
def deactivate() -> None:
    """Remove the saved license key and activation receipt from this user's settings."""
    (state_dir() / LICENSE_FILE).unlink(missing_ok=True)
    activation.forget_receipt()
    out.print("The saved license was removed. AEVRIN_LICENSE or AEVRIN_LICENSE_FILE still apply if set.")


@app.command("verify-build")
def verify_build_command(
    show_all: Annotated[bool, typer.Option("--all", help="List every changed file.")] = False,
) -> None:
    """Check that this copy is an official, unchanged release (exit 1 if it is modified)."""
    build = verify_build(__version__)
    out.print(f"Build: {build.state}")
    if build.reason:
        out.print(f"       {build.reason}")
    for path in build.changed if show_all else build.changed[:20]:
        err.print(f"  changed: {path}")
    raise typer.Exit(1 if build.state == "modified" else 0)
