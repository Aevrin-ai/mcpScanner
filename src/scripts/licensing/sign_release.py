# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Write and sign the release integrity manifest before building a release. Run in CI only.

Usage (in the release workflow, before `python -m build`):
    AEVRIN_RELEASE_SIGNING_KEY="$(cat release-2026-10.key.pem)" python src/scripts/licensing/sign_release.py

The private key comes from the CI secret store, never from the repository. The manifest
and its signature are written into src/mcp_scanner/_release/, so the wheel and the Docker
image carry them. Do not commit these two files: a source checkout has no manifest and
reports itself as a development build.

    --verify   only check an existing manifest (exit 1 if it does not match)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from mcp_scanner import __version__
from mcp_scanner.licensing.integrity import (
    MANIFEST,
    RELEASE_DIR,
    SIGNATURE,
    build_manifest,
    package_dir,
    sign_manifest,
    verify_build,
)

REPO = Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--kid", default=os.environ.get("AEVRIN_RELEASE_KEY_ID", "release-2026-10"))
    args = parser.parse_args()
    root = package_dir()
    if not args.verify:
        pem = os.environ.get("AEVRIN_RELEASE_SIGNING_KEY", "").encode()
        if not pem:
            print(
                "Set AEVRIN_RELEASE_SIGNING_KEY to the release private key (PEM) from the secret store.",
                file=sys.stderr,
            )
            return 2
        passphrase = os.environ.get("AEVRIN_KEY_PASSPHRASE", "").encode() or None
        key = serialization.load_pem_private_key(pem, password=passphrase)
        if not isinstance(key, Ed25519PrivateKey):
            print("The release key is not an Ed25519 key.", file=sys.stderr)
            return 2
        folder = root / RELEASE_DIR
        folder.mkdir(exist_ok=True)
        # The wheel also carries the bundled skills (pyproject.toml force-include), so they are listed too.
        manifest = build_manifest(root, __version__, args.kid, {"bundled/skills": REPO / "src" / "skills"})
        (folder / MANIFEST).write_bytes(json.dumps(manifest, indent=1, sort_keys=True).encode("utf-8"))
        (folder / SIGNATURE).write_bytes((sign_manifest(manifest, key) + "\n").encode("ascii"))
        print(f"Signed manifest for {len(manifest['files'])} files, version {__version__}, key {args.kid}.")
        # The source tree has no bundled skills, so the full check only works on the built package:
        # build the wheel, install it, then run `mcp-scanner license verify-build` there.
        return 0
    result = verify_build(__version__, root)
    print(f"Build check: {result.state} {result.reason}".strip())
    return 0 if result.state == "official" else 1


if __name__ == "__main__":
    sys.exit(main())
