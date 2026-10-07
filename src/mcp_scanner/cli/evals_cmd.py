# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""`mcp-scanner eval`"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from mcp_scanner.cli.common import (
    confirm_host,
    err,
    fail,
    load,
    make_engine,
    out,
    print_json,
    progress,
)
from mcp_scanner.core.errors import ConfigError
from mcp_scanner.evaluation.cases import load_cases
from mcp_scanner.evaluation.metrics import summarize, write_eval_report
from mcp_scanner.evaluation.runner import EvalRunner
from mcp_scanner.scanner.options import ScanOptions, apply_options


def eval_command(
    root: Annotated[Path | None, typer.Option("--root", help="Evals folder (default: src/evals).")] = None,
    case: Annotated[list[str] | None, typer.Option("--case", help="Only run these cases.")] = None,
    allow_host: Annotated[
        bool, typer.Option("--allow-host", help="Run eval servers on this machine without Docker.")
    ] = False,
    ai: Annotated[bool, typer.Option("--ai/--no-ai", help="Include AI review in the eval.")] = False,
    ai_provider: Annotated[str | None, typer.Option("--ai-provider")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Folder for eval reports.")] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    verbose: Annotated[int, typer.Option("--verbose", "-v", count=True)] = 0,
) -> None:
    """Run the eval cases and measure detection quality."""
    settings = load(config, verbose)
    settings = apply_options(
        settings, ScanOptions(ai=ai, ai_provider=ai_provider, allow_host=allow_host or None, sandbox_mode="process")
    )
    folder = root or Path(settings.evals.root)
    try:
        cases = load_cases(folder, case)
    except ConfigError as exc:
        fail(str(exc))
    if not cases:
        fail("No eval cases matched.")
    runner = EvalRunner(settings, make_engine, confirm_host, progress)
    results = runner.run(cases)
    summary = summarize(results)
    json_path, md_path = write_eval_report(summary, results, output or Path(settings.evals.reports_dir))
    if json_out:
        print_json({"summary": asdict(summary), "report": str(json_path)})
    else:
        table = Table("Case", "Kind", "Result", "Grade", "Missed", "False positives", "Seconds")
        for r in results:
            table.add_row(
                r.name,
                "malicious" if r.malicious else "benign",
                "[green]pass[/]" if r.passed else "[red]FAIL[/]",
                r.grade,
                ", ".join(r.false_negatives) or "-",
                ", ".join(r.false_positives) or "-",
                str(r.duration_seconds),
            )
        out.print(table)
        pct = lambda v: "n/a" if v is None else f"{v * 100:.1f}%"  # noqa: E731
        out.print(
            f"Detection {pct(summary.detection_rate)} | precision {pct(summary.precision)} | recall {pct(summary.recall)} | "
            f"false positives {pct(summary.false_positive_rate)} | false negatives {pct(summary.false_negative_rate)} | "
            f"{summary.passed}/{summary.cases} passed in {summary.total_seconds}s"
        )
    err.print(f"Wrote {json_path} and {md_path}")
    raise typer.Exit(0 if summary.passed == summary.cases else 1)
