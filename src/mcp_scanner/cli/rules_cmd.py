# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""`mcp-scanner rules ...`"""

from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from mcp_scanner.cli.common import fail, out, print_json
from mcp_scanner.core.errors import ConfigError
from mcp_scanner.rules.registry import RuleRegistry, id_matches
from mcp_scanner.rules.yaml_rules import load_yaml_rules

app = typer.Typer(help="List and explain security rules.", no_args_is_help=True)


def _registry(rules_dir: list[str] | None) -> RuleRegistry:
    try:
        return RuleRegistry.load(extra_dirs=rules_dir or [])
    except ConfigError as exc:
        fail(str(exc))


@app.command("list")
def list_rules(
    category: Annotated[
        str | None, typer.Option("--category", help="Only this category, for example tool-poisoning.")
    ] = None,
    match: Annotated[str | None, typer.Option("--match", help="Only IDs matching this, for example MCP-EXEC.")] = None,
    rules_dir: Annotated[list[str] | None, typer.Option("--rules-dir")] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List every rule."""
    rules = _registry(rules_dir).all()
    if category:
        rules = [r for r in rules if r.category.value == category]
    if match:
        rules = [r for r in rules if id_matches(r.id, [match])]
    if json_out:
        print_json([r.summary() for r in rules])
        return
    table = Table("ID", "Severity", "Category", "Title", "Needs")
    for rule in rules:
        table.add_row(
            rule.id, rule.severity.value, rule.category.value, rule.title, ", ".join(sorted(rule.needs)) or "-"
        )
    out.print(table)
    out.print(f"{len(rules)} rules")


@app.command("show")
def show_rule(rule_id: str, rules_dir: Annotated[list[str] | None, typer.Option("--rules-dir")] = None) -> None:
    """Explain one rule."""
    rule = _registry(rules_dir).get(rule_id)
    if rule is None:
        fail(f"No rule '{rule_id}'. See `mcp-scanner rules list`.")
    info = rule.summary()
    out.print(f"[bold]{info['id']}[/]  {info['title']}")
    out.print(f"Severity: {info['severity']}   Category: {info['category']}   Origin: {info['origin']}")
    for label, key in (
        ("What it checks", "description"),
        ("Why it matters", "why_it_matters"),
        ("Example attack", "attack_scenario"),
        ("How to fix", "recommendation"),
    ):
        if info.get(key):
            out.print(f"\n[bold]{label}[/]\n{info[key]}")
    if info["needs"]:
        out.print(f"\n[bold]Needs[/]\n{', '.join(info['needs'])}")
    for ref in info["references"]:
        out.print(f"Reference: {ref}")


@app.command("validate")
def validate_rules(folder: str) -> None:
    """Check a folder of YAML rules."""
    try:
        rules = load_yaml_rules(folder)
    except ConfigError as exc:
        fail(str(exc))
    for rule in rules:
        out.print(f"[green]OK[/] {rule.id}  {rule.title}")
    out.print(f"{len(rules)} YAML rule(s) are valid.")
