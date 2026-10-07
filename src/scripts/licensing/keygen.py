# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Make a new Ed25519 signing key pair for Aevrin. Run by Aevrin only.

Usage:
    python src/scripts/licensing/keygen.py --purpose license --out ~/.aevrin-signing
    python src/scripts/licensing/keygen.py --purpose release --out ~/.aevrin-signing
    python src/scripts/licensing/keygen.py --purpose activation --out ~/.aevrin-signing

- The private key is written as a PEM file. Set AEVRIN_KEY_PASSPHRASE to encrypt it.
- It refuses to write inside this repository, so a private key cannot be committed by accident.
- It prints the line to add to src/mcp_scanner/licensing/keys.py (the public key only).

Keep private keys offline (a password manager, a hardware key, or a secrets manager).
The release key goes into the CI secret store. The activation key goes to the license server.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from mcp_scanner.licensing.crypto import b64url

REPO = Path(__file__).resolve().parents[3]
PURPOSES = ("license", "release", "activation")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--purpose", choices=PURPOSES, required=True)
    parser.add_argument("--out", required=True, help="Folder for the private key, outside this repository.")
    parser.add_argument("--kid", help="Key id. Default: <purpose>-<year>-<month>.")
    args = parser.parse_args()

    out = Path(args.out).expanduser().resolve()
    if out == REPO or REPO in out.parents:
        print("Refusing to write a private key inside the repository. Choose a folder outside it.", file=sys.stderr)
        return 2
    kid = args.kid or f"{args.purpose}-{dt.date.today():%Y-%m}"
    path = out / f"{kid}.key.pem"
    if path.exists():
        print(f"{path} already exists. Choose another --kid.", file=sys.stderr)
        return 2

    key = Ed25519PrivateKey.generate()
    passphrase = os.environ.get("AEVRIN_KEY_PASSPHRASE", "").encode()
    encryption = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    out.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(f"Private key: {path}{' (encrypted)' if passphrase else ' (NOT encrypted: protect this file)'}")
    print("Add this line to TRUSTED_KEYS in src/mcp_scanner/licensing/keys.py:")
    print(f'    "{kid}": ("{args.purpose}", "{b64url(public)}"),')
    return 0


if __name__ == "__main__":
    sys.exit(main())
