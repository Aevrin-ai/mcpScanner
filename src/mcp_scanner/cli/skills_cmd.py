# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""`mcp-scanner skills ...`"""

from __future__ import annotations

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
    parse_pairs,
    print_json,
)
from mcp_scanner.core.errors import ScannerError, SkillError
from mcp_scanner.reports.console import ConsoleReporter
from mcp_scanner.scanner.engine import ScanRequest
from mcp_scanner.scanner.options import ScanOptions, apply_options
from mcp_scanner.skills.loader import SKILL_FILE, discover_skills, find_skill, load_skill
from mcp_scanner.skills.runner import SkillRunner

app = typer.Typer(help="List, check, and run skills (SKILL.md scan recipes).", no_args_is_help=True)
DirsOpt = Annotated[list[str] | None, typer.Option("--skills-dir", help="Extra folder with skills.")]


@app.command("list")
def list_skills(skills_dir: DirsOpt = None, json_out: Annotated[bool, typer.Option("--json")] = False) -> None:
    """List available skills."""
    skills, errors = discover_skills(skills_dir)
    if json_out:
        print_json(
            [
                {"name": s.name, "description": s.meta.description, "path": str(s.path), "problems": s.problems}
                for s in skills
            ]
        )
        return
    table = Table("Name", "Description", "Steps", "Path")
    for skill in skills:
        name = skill.name + (" [red](invalid)[/]" if skill.problems else "")
        table.add_row(name, skill.meta.description, str(len(skill.meta.workflow)), str(skill.path.parent))
    out.print(table)
    for error in errors:
        err.print(f"[red]Could not load:[/] {error}")


@app.command("show")
def show_skill(name: str, skills_dir: DirsOpt = None) -> None:
    """Show a skill's inputs, steps, and instructions."""
    try:
        skill = find_skill(name, skills_dir)
    except SkillError as exc:
        fail(str(exc))
    out.print(f"[bold]{skill.name}[/] {skill.meta.version}: {skill.meta.description}")
    for key, spec in skill.meta.inputs.items():
        need = "required" if spec.required else f"default {spec.default!r}"
        out.print(f"  input {key} ({need}): {spec.description}")
    for index, step in enumerate(skill.meta.workflow, start=1):
        out.print(f"  step {index}: {step.action} {step.with_ or ''}")
    out.print()
    out.print(skill.body)


@app.command("validate")
def validate_skills(
    path: Annotated[str | None, typer.Argument(help="A skill folder. Default: all skills.")] = None,
    skills_dir: DirsOpt = None,
) -> None:
    """Check skills for mistakes."""
    bad = 0
    if path:
        folder = Path(path)
        folder = folder.parent if folder.name == SKILL_FILE else folder
        try:
            skills = [load_skill(folder)]
        except SkillError as exc:
            fail(str(exc))
        errors: list[str] = []
    else:
        skills, errors = discover_skills(skills_dir)
    for skill in skills:
        if skill.problems:
            bad += 1
            out.print(f"[red]INVALID[/] {skill.name}: " + "; ".join(skill.problems))
        else:
            out.print(f"[green]OK[/] {skill.name}")
    for error in errors:
        bad += 1
        out.print(f"[red]INVALID[/] {error}")
    raise typer.Exit(1 if bad else 0)


@app.command("run")
def run_skill(
    name: str,
    inputs: Annotated[list[str] | None, typer.Option("--input", "-i", help="Skill input, KEY=VALUE.")] = None,
    skills_dir: DirsOpt = None,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    allow_host: Annotated[bool, typer.Option("--allow-host", help="Allow running servers without Docker.")] = False,
    sandbox: Annotated[str | None, typer.Option("--sandbox")] = None,
    rules_dir: Annotated[list[str] | None, typer.Option("--rules-dir")] = None,
    verbose: Annotated[int, typer.Option("--verbose", "-v", count=True)] = 0,
) -> None:
    """Run a skill's workflow."""
    settings = apply_options(load(config, verbose), ScanOptions(allow_host=allow_host or None, sandbox_mode=sandbox))
    try:
        skill = find_skill(name, skills_dir)
    except SkillError as exc:
        fail(str(exc))

    def show(label: str, text: str) -> None:
        err.print(f"[bold cyan]{label}[/]" if not text else f"[dim]  {text}[/]")

    runner = SkillRunner(
        settings, make_engine, show, ScanRequest(rules_dirs=rules_dir or [], host_confirm=confirm_host)
    )
    try:
        result = runner.run(skill, parse_pairs(inputs, "input"))
    except (SkillError, ScannerError, ValueError) as exc:
        fail(str(exc))
    for report in result.reports:
        ConsoleReporter(show_evidence=settings.output.show_evidence).print(report, out)
    for path in result.files:
        err.print(f"Wrote {path}")
    raise typer.Exit(result.exit_code)
