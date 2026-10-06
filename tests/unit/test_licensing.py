"""License keys, activation, build integrity, branding in reports, and the CI guard.

The tests make their own throwaway keys and trust them only for the length of a test.
Aevrin's real private keys are never needed and never in the repository.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mcp_scanner import __version__
from mcp_scanner.branding import NONCOMMERCIAL_NOTICE, PRODUCT_ID
from mcp_scanner.licensing import activation, crypto, integrity, keys, status
from mcp_scanner.licensing.license import LICENSE_FILE, check_token, find_license_token, state_dir
from mcp_scanner.models.result import ScanReport
from mcp_scanner.reports import REPORTERS, get_reporter

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "scripts" / "licensing"))
import license_server  # noqa: E402

NOW = 1_800_000_000  # a fixed "now" in 2027


@pytest.fixture
def signing(monkeypatch: pytest.MonkeyPatch) -> dict[str, Ed25519PrivateKey]:
    """Throwaway keys for each purpose, trusted only during the test."""
    made = {purpose: Ed25519PrivateKey.generate() for purpose in ("license", "release", "activation")}
    trusted = {
        f"test-{purpose}": (purpose, crypto.b64url(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))
        for purpose, key in made.items()
    }
    monkeypatch.setattr(keys, "TRUSTED_KEYS", trusted)
    return made


def license_token(signing: dict[str, Ed25519PrivateKey], **changes: object) -> str:
    payload: dict[str, object] = {
        "typ": "license",
        "kid": "test-license",
        "product": PRODUCT_ID,
        "lid": "L-TEST-1",
        "licensee": "ACME Corp",
        "edition": "commercial",
        "features": ["*"],
        "iat": NOW - 100,
        "exp": NOW + 365 * 86400,
        "max_major": int(__version__.split(".")[0]),
    }
    payload.update(changes)
    key = signing["activation"] if payload.pop("_sign_with_activation", False) else signing["license"]
    return crypto.sign_token({k: v for k, v in payload.items() if v is not None}, key)


# ---- the token format -------------------------------------------------------------------


def test_valid_license(signing: dict[str, Ed25519PrivateKey]) -> None:
    check = check_token(license_token(signing), __version__, NOW)
    assert check.state == "valid" and check.licensed and check.license is not None
    assert check.license.licensee == "ACME Corp" and check.license.allows("anything")


def test_changed_payload_is_rejected(signing: dict[str, Ed25519PrivateKey]) -> None:
    prefix, body, signature = license_token(signing).split(".")
    payload = json.loads(crypto.unb64url(body))
    payload["licensee"] = "Pirate Ltd"  # try to transfer the license
    forged = f"{prefix}.{crypto.b64url(crypto.canonical_json(payload))}.{signature}"
    assert check_token(forged, __version__, NOW).state == "invalid"


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda t: t.rsplit(".", 1)[0] + "." + crypto.b64url(b"\0" * 64), "signature"),
        (lambda t: "AEVRIN2" + t[7:], "not an AEVRIN1"),
        (lambda t: t + ".extra", "not an AEVRIN1"),
        (lambda t: "garbage", "not an AEVRIN1"),
        (lambda t: t[:-10], ""),
    ],
)
def test_broken_tokens_are_rejected(signing: dict[str, Ed25519PrivateKey], mutate, reason: str) -> None:  # type: ignore[no-untyped-def]
    check = check_token(mutate(license_token(signing)), __version__, NOW)
    assert check.state == "invalid" and reason in check.reason


def test_self_made_key_is_not_trusted(signing: dict[str, Ed25519PrivateKey]) -> None:
    attacker = Ed25519PrivateKey.generate()
    token = crypto.sign_token({"typ": "license", "kid": "test-license", "lid": "x", "licensee": "y"}, attacker)
    assert check_token(token, __version__, NOW).state == "invalid"
    unknown = crypto.sign_token({"typ": "license", "kid": "my-own-key", "lid": "x", "licensee": "y"}, attacker)
    assert "unknown key" in check_token(unknown, __version__, NOW).reason


def test_a_key_for_one_purpose_cannot_sign_another(signing: dict[str, Ed25519PrivateKey]) -> None:
    # The activation key lives on an internet-facing server. If it leaks, it must not mint licenses.
    token = license_token(signing, kid="test-activation", _sign_with_activation=True)
    check = check_token(token, __version__, NOW)
    assert check.state == "invalid" and "not trusted for license" in check.reason


def test_receipt_is_not_a_license(signing: dict[str, Ed25519PrivateKey]) -> None:
    receipt = crypto.sign_token({"typ": "activation", "kid": "test-license", "lid": "L"}, signing["license"])
    assert "not a 'license' token" in check_token(receipt, __version__, NOW).reason


@pytest.mark.parametrize(
    ("changes", "state"),
    [
        ({"exp": NOW - 3600}, "expired"),
        ({"exp": NOW - 60}, "valid"),  # within the clock skew allowance
        ({"nbf": NOW + 86400}, "not-yet-valid"),
        ({"product": "other-product"}, "wrong-product"),
        ({"max_major": 0}, "wrong-version"),
        ({"edition": "platinum"}, "invalid"),
        ({"online": True, "activation": "http://evil.example.com"}, "invalid"),
        ({"exp": None}, "valid"),  # perpetual
    ],
)
def test_license_rules(signing: dict[str, Ed25519PrivateKey], changes: dict, state: str) -> None:
    assert check_token(license_token(signing, **changes), __version__, NOW).state == state


# ---- where the key comes from -------------------------------------------------------------


def test_license_sources(
    signing: dict[str, Ed25519PrivateKey], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert find_license_token() is None
    saved = state_dir() / LICENSE_FILE
    saved.parent.mkdir(parents=True, exist_ok=True)
    saved.write_text("saved-key", encoding="utf-8")
    assert find_license_token() == ("saved-key", str(saved))
    secret = tmp_path / "aevrin_license"
    secret.write_text("secret-key\n", encoding="utf-8")
    monkeypatch.setenv("AEVRIN_LICENSE_FILE", str(secret))
    assert find_license_token() == ("secret-key", str(secret))
    monkeypatch.setenv("AEVRIN_LICENSE", "inline-key")
    assert find_license_token() == ("inline-key", "AEVRIN_LICENSE")


def test_status_notices(signing: dict[str, Ed25519PrivateKey], monkeypatch: pytest.MonkeyPatch) -> None:
    assert status.license_notice(status.check_license(now=NOW)) == NONCOMMERCIAL_NOTICE
    monkeypatch.setenv("AEVRIN_LICENSE", license_token(signing))
    assert status.license_notice(status.check_license(now=NOW)).startswith("Licensed to ACME Corp (commercial")
    monkeypatch.setenv("AEVRIN_LICENSE", license_token(signing, exp=NOW - 86400 * 10))
    notice = status.license_notice(status.check_license(now=NOW))
    assert notice.startswith("License problem:") and NONCOMMERCIAL_NOTICE in notice


def test_clock_set_back_is_noticed(signing: dict[str, Ed25519PrivateKey], monkeypatch: pytest.MonkeyPatch) -> None:
    # The license expired ten days ago, and the scanner ran today.
    monkeypatch.setenv("AEVRIN_LICENSE", license_token(signing, iat=NOW - 400 * 86400, exp=NOW - 10 * 86400))
    assert status.check_license(now=NOW).state == "expired"
    # Someone sets the clock back a month to make the license look valid again.
    assert status.check_license(now=NOW - 30 * 86400).state == "clock"


# ---- online activation ----------------------------------------------------------------------


@pytest.fixture
def server(signing: dict[str, Ed25519PrivateKey], tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """The reference license server, called in-process instead of over HTTP."""
    db = license_server.open_db(str(tmp_path / "licenses.sqlite"))
    calls: list[str] = []

    def request_receipt(lic, token, iid, version, client=None):  # type: ignore[no-untyped-def]
        calls.append(iid)
        code, body = license_server.activate(db, signing["activation"], "test-activation",
                                             {"license": token, "installation_id": iid, "version": version}, NOW)  # fmt: skip
        if code == 200:
            return body["receipt"]
        raise activation.ActivationError(body["error"], revoked=code == 410)

    monkeypatch.setattr(activation, "request_receipt", request_receipt)
    return db, calls


def online_license(signing: dict[str, Ed25519PrivateKey], **changes: object) -> str:
    return license_token(
        signing, online=True, activation="https://license.example.com", seats=2, grace_days=14, **changes
    )


def test_installation_id(monkeypatch: pytest.MonkeyPatch) -> None:
    first = activation.installation_id()
    assert activation.installation_id() == first and uuid.UUID(first)
    fixed = str(uuid.uuid4())
    monkeypatch.setenv("AEVRIN_INSTALLATION_ID", fixed)
    assert activation.installation_id() == fixed
    monkeypatch.setenv("AEVRIN_INSTALLATION_ID", "not-a-uuid")
    with pytest.raises(ValueError):
        activation.installation_id()


def test_activation_then_offline_grace_then_required(signing, server, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    token = online_license(signing)
    check = check_token(token, __version__, NOW)
    assert activation.apply(check, token, __version__, NOW, network=True).state == "valid"
    # 40 days later the server cannot be reached: the 30-day receipt has ended, grace applies.
    later = check_token(token, __version__, NOW + 40 * 86400)
    monkeypatch.setattr(
        activation, "request_receipt", lambda *a, **k: (_ for _ in ()).throw(activation.ActivationError("offline"))
    )
    assert activation.apply(later, token, __version__, NOW + 40 * 86400, network=True).state == "grace"
    much_later = check_token(token, __version__, NOW + 50 * 86400)
    assert (
        activation.apply(much_later, token, __version__, NOW + 50 * 86400, network=True).state == "activation-required"
    )


def test_offline_run_without_receipt_is_not_licensed(signing, server) -> None:  # type: ignore[no-untyped-def]
    token = online_license(signing)
    check = check_token(token, __version__, NOW)
    assert activation.apply(check, token, __version__, NOW, network=False).state == "activation-required"


def test_seat_limit_and_revocation(signing, server, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    db, _ = server
    token = online_license(signing)
    for _ in range(2):
        monkeypatch.setenv("AEVRIN_INSTALLATION_ID", str(uuid.uuid4()))
        activation.forget_receipt()
        assert activation.apply(check_token(token, __version__, NOW), token, __version__, NOW, True).state == "valid"
    monkeypatch.setenv("AEVRIN_INSTALLATION_ID", str(uuid.uuid4()))  # a third machine
    activation.forget_receipt()
    third = activation.apply(check_token(token, __version__, NOW), token, __version__, NOW, True)
    assert third.state == "activation-required" and "seat limit" in " ".join(third.notes)
    with db:
        db.execute("INSERT INTO revoked VALUES ('L-TEST-1', 0, 'chargeback')")
    assert activation.apply(check_token(token, __version__, NOW), token, __version__, NOW, True).state == "revoked"


def test_edited_or_copied_receipts_are_ignored(signing, server, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    token = online_license(signing)
    activation.apply(check_token(token, __version__, NOW), token, __version__, NOW, True)
    lic = check_token(token, __version__, NOW).license
    assert lic is not None and activation.saved_receipt(lic, activation.installation_id()) is not None
    # Copied to another installation: the receipt names the first installation only.
    assert activation.saved_receipt(lic, str(uuid.uuid4())) is None
    # Edited to last longer: the signature breaks.
    path = state_dir() / activation.RECEIPT_FILE
    prefix, body, sig = json.loads(path.read_text(encoding="utf-8"))["receipt"].split(".")
    payload = json.loads(crypto.unb64url(body))
    payload["exp"] += 10 * 365 * 86400
    path.write_text(
        json.dumps({"receipt": f"{prefix}.{crypto.b64url(crypto.canonical_json(payload))}.{sig}"}), encoding="utf-8"
    )
    assert activation.saved_receipt(lic, activation.installation_id()) is None


def test_server_rejects_forged_licenses(signing: dict[str, Ed25519PrivateKey], tmp_path: Path) -> None:
    db = license_server.open_db(str(tmp_path / "db.sqlite"))
    attacker = Ed25519PrivateKey.generate()
    forged = crypto.sign_token({"typ": "license", "kid": "test-license", "lid": "x", "licensee": "y"}, attacker)
    code, body = license_server.activate(db, signing["activation"], "test-activation",
                                         {"license": forged, "installation_id": str(uuid.uuid4())}, NOW)  # fmt: skip
    assert code == 401 and "not valid" in body["error"]


# ---- build integrity --------------------------------------------------------------------------


@pytest.fixture
def package(tmp_path: Path) -> Path:
    root = tmp_path / "mcp_scanner"
    shutil.copytree(integrity.package_dir(), root, ignore=shutil.ignore_patterns("__pycache__"))
    return root


def sign(root: Path, key: Ed25519PrivateKey, version: str = __version__, kid: str = "test-release") -> None:
    manifest = integrity.build_manifest(root, version, kid)
    folder = root / integrity.RELEASE_DIR
    folder.mkdir(exist_ok=True)
    (folder / integrity.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    (folder / integrity.SIGNATURE).write_text(integrity.sign_manifest(manifest, key), encoding="utf-8")


def test_official_then_modified(signing: dict[str, Ed25519PrivateKey], package: Path) -> None:
    assert integrity.verify_build(__version__, package).state == "development"
    sign(package, signing["release"])
    assert integrity.verify_build(__version__, package).state == "official"
    (package / "branding.py").write_text("NONCOMMERCIAL_NOTICE = ''\n", encoding="utf-8")
    (package / "patch.py").write_text("x = 1\n", encoding="utf-8")
    result = integrity.verify_build(__version__, package)
    assert result.state == "modified" and result.changed == ["branding.py", "patch.py (added)"]


def test_rewritten_manifest_is_caught(signing: dict[str, Ed25519PrivateKey], package: Path) -> None:
    sign(package, signing["release"])
    (package / "branding.py").write_text("x = 1\n", encoding="utf-8")
    # The attacker writes fresh hashes but cannot sign them with Aevrin's key.
    manifest = integrity.build_manifest(package, __version__, "test-release")
    (package / integrity.RELEASE_DIR / integrity.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    assert "not genuine" in integrity.verify_build(__version__, package).reason
    # Signing with their own key does not help either.
    sign(package, Ed25519PrivateKey.generate())
    assert integrity.verify_build(__version__, package).state == "modified"


def test_manifest_for_another_version(signing: dict[str, Ed25519PrivateKey], package: Path) -> None:
    sign(package, signing["release"], version="0.9.0")
    assert "another version" in integrity.verify_build(__version__, package).reason


def test_manifest_covers_bundled_files(signing: dict[str, Ed25519PrivateKey], package: Path, tmp_path: Path) -> None:
    skills = tmp_path / "skills"
    (skills / "quick").mkdir(parents=True)
    (skills / "quick" / "SKILL.md").write_text("x", encoding="utf-8")
    manifest = integrity.build_manifest(package, __version__, "test-release", {"bundled/skills": skills})
    assert "bundled/skills/quick/SKILL.md" in manifest["files"]


# ---- branding in every report ------------------------------------------------------------------


@pytest.mark.parametrize("fmt", sorted(REPORTERS))
def test_every_report_carries_branding_and_license(fmt: str) -> None:
    report = ScanReport(scanner_version=__version__)
    assert report.product is None  # as if the engine step that fills it had been removed
    text = get_reporter(fmt).render(report)
    assert "Aevrin" in text and "noncommercial" in text.lower()
    assert report.product is not None and report.product.build == "development"


def test_licensed_reports_name_the_licensee(
    signing: dict[str, Ed25519PrivateKey], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "AEVRIN_LICENSE", license_token(signing, iat=int(time.time()) - 100, exp=int(time.time()) + 86400)
    )
    text = get_reporter("markdown").render(ScanReport(scanner_version=__version__))
    assert "Licensed to ACME Corp (commercial license L-TEST-1" in text and NONCOMMERCIAL_NOTICE not in text


# ---- tools and CI guard ------------------------------------------------------------------------


def test_keygen_refuses_to_write_inside_the_repository() -> None:
    script = ROOT / "src" / "scripts" / "licensing" / "keygen.py"
    result = subprocess.run(
        [sys.executable, str(script), "--purpose", "license", "--out", str(ROOT / "tmp-keys")],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert result.returncode == 2 and "inside the repository" in result.stderr
    assert not (ROOT / "tmp-keys").exists()


def test_licensing_guard_passes_on_this_repository() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "src" / "scripts" / "check_licensing.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout


def test_licensing_guard_catches_a_changed_protected_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sys.path.insert(0, str(ROOT / "src" / "scripts"))
    import check_licensing

    pins = tmp_path / "pins"
    pins.write_text(
        check_licensing.PINS.read_text(encoding="utf-8").replace(
            "src/mcp_scanner/licensing/keys.py", "src/mcp_scanner/licensing/keys.py.renamed"
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(check_licensing, "PINS", pins)
    errors: list[str] = []
    check_licensing.check_pins(errors)
    assert any("protected file added: src/mcp_scanner/licensing/keys.py." in e for e in errors)
    assert any("removed: src/mcp_scanner/licensing/keys.py.renamed" in e for e in errors)


def test_real_keys_are_public_keys_only() -> None:
    text = (ROOT / "src" / "mcp_scanner" / "licensing" / "keys.py").read_text(encoding="utf-8")
    assert "PRIVATE KEY" not in text
    for purpose, raw in keys.TRUSTED_KEYS.values():
        assert purpose in ("license", "release", "activation") and len(crypto.unb64url(raw)) == 32
