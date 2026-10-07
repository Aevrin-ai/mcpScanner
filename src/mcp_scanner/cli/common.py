# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Helpers shared by CLI commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import NoReturn

import typer
from dotenv import load_dotenv
from rich.console import Console

from mcp_scanner.ai.review import AIReviewService
from mcp_scanner.ai.setup import SetupPlanner
from mcp_scanner.config.loader import load_settings
from mcp_scanner.config.settings import Settings
from mcp_scanner.core.errors import ScannerError
from mcp_scanner.logging.setup import configure_logging
from mcp_scanner.models.server import ServerSpec
from mcp_scanner.scanner.engine import ScanEngine

# Results go to stdout. Progress, prompts, and logs go to stderr, so stdout can be piped.
out = Console()
err = Console(stderr=True)

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def load(config: Path | None, verbose: int) -> Settings:
    load_dotenv(override=False)
    try:
        settings = load_settings(config)
    except ScannerError as exc:
        fail(str(exc))
    configure_logging(settings.logging, verbose)
    return settings


def fail(message: str, code: int = EXIT_ERROR) -> NoReturn:
    err.print(f"[bold red]Error:[/] {message}")
    raise typer.Exit(code)


def parse_pairs(values: list[str] | None, what: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for item in values or []:
        sep = "=" if what == "env" else ":" if ":" in item and "=" not in item else "="
        key, found, value = item.partition(sep)
        if not found or not key.strip():
            fail(f"--{what} needs KEY{sep}VALUE, got '{item}'")
        pairs[key.strip()] = value.strip()
    return pairs


def confirm_host(spec: ServerSpec) -> bool:
    """Ask before running a server on this machine without Docker. Never asks when not interactive."""
    if not sys.stdin.isatty():
        return False
    err.print(
        f"\n[bold yellow]Warning:[/] server [bold]{spec.name}[/] would run on this machine without Docker.\n"
        f"  Command: {spec.display_target()}\n"
        "  The process sandbox limits time, memory, and environment, but it is NOT a security wall."
    )
    return typer.confirm("Run it anyway?", default=False, err=True)


def make_engine(settings: Settings) -> ScanEngine:
    reviewer = AIReviewService(settings.ai) if settings.ai.enabled else None
    # The same AI provider can also work out how to start a repository server (--run).
    planner = SetupPlanner(settings.ai) if settings.ai.enabled and settings.ai.setup != "never" else None
    return ScanEngine(settings, ai_reviewer=reviewer, setup_planner=planner)


def print_json(data: object) -> None:
    """Write JSON straight to stdout. ASCII only, so any console code page can show it,
    and no line wrapping, so the output always parses."""
    sys.stdout.write(json.dumps(data, indent=2, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def progress(message: str) -> None:
    err.print(f"[dim]{message}[/]")
