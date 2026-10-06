# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""CI guard for licensing, branding, and protected files. Fails on accidental removal or change.

    python src/scripts/check_licensing.py             # every pull request
    python src/scripts/check_licensing.py --deps      # also check dependency licenses
    python src/scripts/check_licensing.py --release   # also the checks a release needs
    python src/scripts/check_licensing.py --update-pins

Protected files (licensing code, branding, legal texts, CI workflows) are pinned by hash in
src/scripts/protected-files.sha256. Changing one makes this check fail until the pins are
updated with --update-pins in the same pull request. That makes every change deliberate
and visible to the reviewers named in .github/CODEOWNERS.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as md
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

# sha256 of the official PolyForm Noncommercial 1.0.0 text (polyformproject.org, Markdown form).
POLYFORM_NC_SHA256 = "ffcca38841adb694b6f380647e15f17c446a4d1656fed51a1e2041d064c94cc8"
SPDX = "PolyForm-Noncommercial-1.0.0"
HEADER = "# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0"
REQUIRED_NOTICES = (
    "Required Notice: Copyright (c) 2026 Aevrin.",
    "Required Notice: Aevrin MCP Scanner is licensed under the PolyForm Noncommercial License 1.0.0",
    "Required Notice: Commercial use requires a separate commercial license from Aevrin.",
    'Required Notice: "Aevrin" and "Aevrin MCP Scanner" are trademarks of Aevrin.',
)
PINS = ROOT / "src" / "scripts" / "protected-files.sha256"
PROTECTED = (
    "LICENSE",
    "NOTICE",
    "COMMERCIAL-LICENSE.md",
    "TRADEMARKS.md",
    ".gitattributes",
    "src/mcp_scanner/branding.py",
    "src/mcp_scanner/licensing/*.py",
    "src/scripts/check_licensing.py",
    "src/scripts/licensing/*.py",
    ".github/CODEOWNERS",
    ".github/workflows/*.yml",
)
# Code that must keep showing the branding and license status. (file, text that must be in it)
BRANDING_HOOKS = (
    ("src/mcp_scanner/scanner/engine.py", "product=product_info()"),
    ("src/mcp_scanner/reports/base.py", "def ensure_product("),
    ("src/mcp_scanner/reports/console.py", "footer_lines(report)"),
    ("src/mcp_scanner/reports/markdown.py", "footer_lines(report)"),
    ("src/mcp_scanner/reports/sarif.py", "ensure_product(report)"),
    ("src/mcp_scanner/reports/json_report.py", "ensure_product(report)"),
    ("src/mcp_scanner/cli/app.py", 'epilog=f"{COPYRIGHT}'),
    ("src/mcp_scanner/cli/app.py", "license_cmd.app"),
    ("src/mcp_scanner/mcp/transports/http.py", "USER_AGENT"),
)
ALLOWED_DEP_LICENSES = re.compile(r"MIT|BSD|Apache|ISC|PSF|Python Software Foundation|MPL|Unlicense|Zlib|0BSD", re.I)
COPYLEFT = re.compile(r"\b(?:A?GPL|SSPL|EUPL|OSL)\b|GNU (?:Affero )?General Public", re.I)


def text(path: Path) -> str:
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


def protected_files() -> list[Path]:
    found: list[Path] = []
    for pattern in PROTECTED:
        found += sorted(p for p in ROOT.glob(pattern) if p.is_file())
    return found


def pin_lines() -> list[str]:
    lines = []
    for path in protected_files():
        digest = hashlib.sha256(text(path).encode("utf-8")).hexdigest()
        lines.append(f"{digest}  {path.relative_to(ROOT).as_posix()}")
    return lines


def check_pins(errors: list[str]) -> None:
    if not PINS.is_file():
        errors.append(f"{PINS.name} is missing. Run with --update-pins.")
        return
    expected = {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in text(PINS).splitlines() if "  " in line}
    actual = {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in pin_lines()}
    for path in sorted(set(expected) | set(actual)):
        if expected.get(path) != actual.get(path):
            state = "removed" if path not in actual else "added" if path not in expected else "changed"
            errors.append(f"protected file {state}: {path}. If this is intended, run --update-pins in the same PR.")


def check_legal(errors: list[str]) -> None:
    license_file = ROOT / "LICENSE"
    if not license_file.is_file():
        errors.append("LICENSE is missing")
    elif hashlib.sha256(text(license_file).encode()).hexdigest() != POLYFORM_NC_SHA256:
        errors.append("LICENSE is not the official PolyForm Noncommercial 1.0.0 text")
    notice = text(ROOT / "NOTICE") if (ROOT / "NOTICE").is_file() else ""
    for line in REQUIRED_NOTICES:
        if line not in notice:
            errors.append(f"NOTICE is missing: {line[:70]}")
    for name in ("COMMERCIAL-LICENSE.md", "TRADEMARKS.md"):
        if not (ROOT / name).is_file():
            errors.append(f"{name} is missing")


def check_headers(errors: list[str]) -> None:
    for folder in ("src/mcp_scanner", "src/scripts"):
        for path in sorted((ROOT / folder).rglob("*.py")):
            head = text(path).splitlines()[:3]
            if HEADER not in head:
                errors.append(f"missing SPDX header: {path.relative_to(ROOT).as_posix()}")


def check_metadata(errors: list[str]) -> None:
    project = tomllib.loads(text(ROOT / "pyproject.toml"))["project"]
    if project.get("license") != SPDX:
        errors.append(f"pyproject.toml license must be {SPDX}")
    if not {"LICENSE", "NOTICE"} <= set(project.get("license-files", [])):
        errors.append("pyproject.toml license-files must include LICENSE and NOTICE")
    docker = text(ROOT / "Dockerfile")
    for label in (f'org.opencontainers.image.licenses="{SPDX}"', 'org.opencontainers.image.vendor="Aevrin"'):
        if label not in docker:
            errors.append(f"Dockerfile is missing the label {label}")
    from mcp_scanner import branding

    expected = {"PRODUCT_NAME": "Aevrin MCP Scanner", "VENDOR": "Aevrin", "LICENSE_ID": SPDX}
    for name, value in expected.items():
        if getattr(branding, name, None) != value:
            errors.append(f"branding.{name} must be {value!r}")
    if SPDX not in text(ROOT / "README.md"):
        errors.append("README.md must name the license")


def check_hooks(errors: list[str]) -> None:
    for rel, needle in BRANDING_HOOKS:
        path = ROOT / rel
        if not path.is_file() or needle not in text(path):
            errors.append(f"branding or license hook removed: {rel} must contain {needle!r}")


def check_untracked_release(errors: list[str]) -> None:
    try:
        tracked = subprocess.run(
            ["git", "ls-files", "src/mcp_scanner/_release"], cwd=ROOT, capture_output=True, text=True, check=False
        ).stdout.split()
    except OSError:
        return
    for path in tracked:
        if path.endswith(("manifest.json", "manifest.sig")):
            errors.append(f"{path} must not be committed: only the release workflow writes it")


def check_release(errors: list[str]) -> None:
    if "not set yet" in text(ROOT / "COMMERCIAL-LICENSE.md"):
        errors.append("COMMERCIAL-LICENSE.md: set the commercial licensing contact before a release")
    from mcp_scanner.licensing.keys import TRUSTED_KEYS

    purposes = {purpose for purpose, _ in TRUSTED_KEYS.values()}
    for needed in ("license", "release"):
        if needed not in purposes:
            errors.append(f"licensing/keys.py has no {needed} key")


def _applies(requirement: str) -> bool:
    """False for optional extras and for requirements whose environment marker does not match here."""
    if "extra ==" in requirement:
        return False
    try:
        from packaging.requirements import Requirement

        marker = Requirement(requirement).marker
        return marker is None or marker.evaluate()
    except Exception:
        return True


def runtime_dependencies() -> set[str]:
    """Names of every installed distribution the runtime dependencies pull in."""
    project = tomllib.loads(text(ROOT / "pyproject.toml"))["project"]
    todo = [re.split(r"[<>=!~;\[ ]", req, maxsplit=1)[0] for req in project["dependencies"]]
    seen: set[str] = set()
    while todo:
        name = todo.pop().lower().replace("_", "-")
        if name in seen:
            continue
        seen.add(name)
        try:
            requires = md.requires(name) or []
        except md.PackageNotFoundError:
            continue
        todo += [re.split(r"[<>=!~;\[ (]", r, maxsplit=1)[0] for r in requires if _applies(r)]
    return seen


def check_dependencies(errors: list[str], warnings: list[str]) -> None:
    for name in sorted(runtime_dependencies()):
        try:
            meta = md.metadata(name)
        except md.PackageNotFoundError:
            warnings.append(f"dependency {name} is not installed, license not checked")
            continue
        classifiers = [c for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
        found = " ".join([meta.get("License-Expression") or "", (meta.get("License") or "")[:200], *classifiers])
        if COPYLEFT.search(found) and not re.search(r"LGPL|Lesser", found):
            errors.append(f"dependency {name} has a copyleft license ({found.strip()[:80]})")
        elif not ALLOWED_DEP_LICENSES.search(found):
            warnings.append(f"dependency {name}: review its license ({found.strip()[:80] or 'not stated'})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--deps", action="store_true")
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--update-pins", action="store_true")
    args = parser.parse_args()
    if args.update_pins:
        PINS.write_bytes(("\n".join(pin_lines()) + "\n").encode("utf-8"))
        print(f"Updated {PINS.relative_to(ROOT).as_posix()} ({len(pin_lines())} files).")
        return 0
    errors: list[str] = []
    warnings: list[str] = []
    check_legal(errors)
    check_headers(errors)
    check_metadata(errors)
    check_hooks(errors)
    check_pins(errors)
    check_untracked_release(errors)
    if args.release:
        check_release(errors)
    if args.deps:
        check_dependencies(errors, warnings)
    for warning in warnings:
        print(f"warning: {warning}")
    for error in errors:
        print(f"error: {error}")
    print(f"Licensing check: {len(errors)} error(s), {len(warnings)} warning(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
