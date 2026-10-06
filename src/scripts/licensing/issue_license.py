# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Issue a signed license key for a customer. Run by Aevrin only, with the private license key.

Usage:
    python src/scripts/licensing/issue_license.py --key ~/.aevrin-signing/license-2026-10.key.pem \\
        --licensee "ACME Corp" --edition commercial --days 365 --features "*" --max-major 1 \\
        [--online --activation https://license.example.com --seats 10] --out acme.lic

The key file may be encrypted: set AEVRIN_KEY_PASSPHRASE. The output is one line that starts
with AEVRIN1. Send it to the customer. It contains no secret, but it identifies them.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from mcp_scanner.branding import PRODUCT_ID
from mcp_scanner.licensing.crypto import sign_token
from mcp_scanner.licensing.license import EDITIONS, check_token


def load_private_key(path: Path) -> tuple[Ed25519PrivateKey, str]:
    """The key and its id (the file name without .key.pem)."""
    passphrase = os.environ.get("AEVRIN_KEY_PASSPHRASE", "").encode() or None
    key = serialization.load_pem_private_key(path.read_bytes(), password=passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("Not an Ed25519 private key")
    return key, path.name.removesuffix(".key.pem")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--licensee", required=True)
    parser.add_argument("--edition", choices=EDITIONS, default="commercial")
    parser.add_argument("--features", default="*", help="Comma separated, or * for all.")
    parser.add_argument("--days", type=int, help="Valid for this many days. Leave out for a perpetual license.")
    parser.add_argument("--max-major", type=int, help="Newest major version covered, for example 1.")
    parser.add_argument("--seats", type=int, help="Installations allowed (online licenses).")
    parser.add_argument("--online", action="store_true", help="Installations must activate with the server.")
    parser.add_argument("--activation", help="https URL of the license server (online licenses).")
    parser.add_argument("--grace-days", type=int, default=14)
    parser.add_argument("--lid", help="License id. Default: L-<year>-<random>.")
    parser.add_argument("--out", type=Path, help="Write the key to this .lic file too.")
    args = parser.parse_args()

    key, kid = load_private_key(args.key.expanduser())
    now = int(time.time())
    payload = {
        "typ": "license",
        "kid": kid,
        "product": PRODUCT_ID,
        "lid": args.lid or f"L-{time.strftime('%Y')}-{secrets.token_hex(4).upper()}",
        "licensee": args.licensee,
        "edition": args.edition,
        "features": [f.strip() for f in args.features.split(",") if f.strip()],
        "iat": now,
        "nbf": now,
        "exp": now + args.days * 86400 if args.days else None,
        "max_major": args.max_major,
        "seats": args.seats,
        "online": args.online,
        "activation": args.activation,
        "grace_days": args.grace_days,
    }
    token = sign_token({k: v for k, v in payload.items() if v is not None}, key)
    # Check it the same way the scanner will, so a broken key is never sent to a customer.
    check = check_token(token, f"{args.max_major or 1}.0.0")
    if check.state != "valid":
        print(f"The new license does not verify ({check.state}: {check.reason}).", file=sys.stderr)
        print("Is the public key for this private key listed in licensing/keys.py?", file=sys.stderr)
        return 1
    if args.out:
        args.out.write_text(token + "\n", encoding="utf-8")
        print(f"Wrote {args.out}", file=sys.stderr)
    print(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
