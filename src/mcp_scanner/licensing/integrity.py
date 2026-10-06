# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Is this copy an official, unchanged release?

Each official release ships `mcp_scanner/_release/manifest.json`: the SHA-256 hash of
every file in the package, signed with Aevrin's release key (Ed25519). On every run
the scanner checks the signature, then hashes its own files and compares:

  official     the signature is valid and every file matches
  modified     the signature is invalid, or a file was changed, removed, or added
  development  there is no manifest: a source checkout or a local build

A hash alone only says "these bytes changed". The signature says the list of hashes
came from Aevrin, so someone who changes a file cannot simply write new hashes.

This detects changes. It cannot stop someone who also edits this file to always say
"official". That is why reports show the result, and why the threat model in
docs/licensing-threat-model.md lists it as a limit.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_scanner.branding import PRODUCT_ID
from mcp_scanner.licensing.crypto import TokenError, b64url, canonical_json, unb64url, verify_bytes

RELEASE_DIR = "_release"
MANIFEST = "manifest.json"
SIGNATURE = "manifest.sig"
SKIP_PARTS = {"__pycache__", RELEASE_DIR}
SKIP_SUFFIXES = (".pyc", ".pyo")


@dataclass
class BuildCheck:
    state: str  # "official", "modified", or "development"
    version: str | None = None
    reason: str = ""
    changed: list[str] = field(default_factory=list)


def package_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def file_hashes(root: Path) -> dict[str, str]:
    """SHA-256 of every file that belongs to the package, by its path inside the package."""
    hashes = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if not path.is_file() or SKIP_PARTS & set(rel.parts) or path.suffix in SKIP_SUFFIXES:
            continue
        hashes[rel.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def build_manifest(root: Path, version: str, kid: str, extra: dict[str, Path] | None = None) -> dict[str, Any]:
    """The manifest for the package at `root`. `extra` maps folders the build copies into the
    package (for example {"bundled/skills": src/skills}) to where they come from."""
    files = file_hashes(root)
    for prefix, folder in (extra or {}).items():
        files.update({f"{prefix}/{rel}": digest for rel, digest in file_hashes(folder).items()})
    return {"v": 1, "product": PRODUCT_ID, "version": version, "kid": kid, "files": dict(sorted(files.items()))}


def sign_manifest(manifest: dict[str, Any], private_key: Any) -> str:
    """The signature text for a manifest. Only the release tool calls this."""
    return b64url(private_key.sign(canonical_json(manifest)))


def verify_build(version: str, root: Path | None = None) -> BuildCheck:
    root = root or package_dir()
    folder = root / RELEASE_DIR
    if not (folder / MANIFEST).is_file():
        return BuildCheck("development", reason="no release manifest: a source checkout or a local build")
    try:
        manifest = json.loads((folder / MANIFEST).read_text(encoding="utf-8"))
        signature = unb64url((folder / SIGNATURE).read_text(encoding="utf-8").strip())
        if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict):
            raise TokenError("malformed manifest")
        verify_bytes(canonical_json(manifest), signature, str(manifest.get("kid")), "release")
    except (OSError, ValueError, TokenError) as exc:
        return BuildCheck("modified", reason=f"the release manifest is not genuine: {exc}")
    if manifest.get("product") != PRODUCT_ID or manifest.get("version") != version:
        return BuildCheck("modified", manifest.get("version"), "the release manifest is for another version")
    expected: dict[str, str] = manifest["files"]
    actual = file_hashes(root)
    changed = sorted(p for p in expected if actual.get(p) != expected[p])
    added = sorted(p for p in actual if p not in expected)
    if changed or added:
        return BuildCheck(
            "modified",
            version,
            f"{len(changed)} changed or missing, {len(added)} added",
            changed + [f"{p} (added)" for p in added],
        )
    return BuildCheck("official", version)
