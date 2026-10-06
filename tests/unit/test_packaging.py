"""The wheel builder skips files matched by .gitignore. A pattern like "reports/" once
dropped the mcp_scanner.reports package from the wheel. Ignore patterns for root
folders must start with "/" so they cannot hit a package folder."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "mcp_scanner"


def test_gitignore_cannot_hide_a_package_folder() -> None:
    packages = {p.name for p in PACKAGE.rglob("*") if p.is_dir() and (p / "__init__.py").exists()}
    patterns = [
        line.strip().rstrip("/")
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith(("#", "/", "!"))
    ]
    clashes = sorted(set(patterns) & packages)
    assert not clashes, f".gitignore would drop these packages from the wheel: {clashes}"


def test_bundled_data_files_exist() -> None:
    for name in ("known_malicious_packages.json", "popular_packages.json"):
        assert (PACKAGE / "data" / name).is_file()
    assert (ROOT / "src" / "skills" / "quick-scan" / "SKILL.md").is_file()
