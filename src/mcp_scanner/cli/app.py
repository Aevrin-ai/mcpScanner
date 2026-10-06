# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""The `mcp-scanner` command line app."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.table import Table

from mcp_scanner import PRODUCT_NAME, __version__
from mcp_scanner.branding import COPYRIGHT, NONCOMMERCIAL_NOTICE
from mcp_scanner.cli import evals_cmd, license_cmd, rules_cmd, skills_cmd
from mcp_scanner.cli.common import (
    EXIT_ERROR,
    confirm_host,
    err,
    fail,
    load,
    make_engine,
    out,
    parse_pairs,
    print_json,
    progress,
)
from mcp_scanner.config.discovery import known_config_paths
from mcp_scanner.config.mcp_config import parse_client_config
from mcp_scanner.config.targets import TargetRequest
from mcp_scanner.core.errors import ScannerError
from mcp_scanner.licensing.status import product_info
from mcp_scanner.reports import REPORTERS, get_reporter, load_report, report_to_dict
from mcp_scanner.reports.console import ConsoleReporter
from mcp_scanner.scanner.engine import ScanRequest, exit_code
from mcp_scanner.scanner.options import ScanOptions, apply_options, write_reports

app = typer.Typer(
    name="mcp-scanner",
    help=f"{PRODUCT_NAME}: find security problems in MCP servers and tools.",
    epilog=f"{COPYRIGHT}. {NONCOMMERCIAL_NOTICE} See: mcp-scanner license status",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)
app.add_typer(rules_cmd.app, name="rules")
app.add_typer(skills_cmd.app, name="skills")
app.add_typer(license_cmd.app, name="license")
app.command("eval")(evals_cmd.eval_command)

ConfigOpt = Annotated[Path | None, typer.Option("--config", "-c", help="Scanner config file (YAML).")]
VerboseOpt = Annotated[int, typer.Option("--verbose", "-v", count=True, help="More logs on stderr (-vv for debug).")]


@app.command()
def scan(
    target: Annotated[
        str | None, typer.Argument(help="Command, URL, GitHub link, folder, MCP config file, or tools file.")
    ] = None,
    discover: Annotated[
        bool, typer.Option("--discover", help="Scan every server in known MCP client configs.")
    ] = False,
    server: Annotated[
        list[str] | None, typer.Option("--server", "-s", help="Only scan servers with this name.")
    ] = None,
    config: ConfigOpt = None,
    dynamic: Annotated[
        bool | None,
        typer.Option("--dynamic/--static", help="Watch the live server: relist tools, read prompts, call safe tools."),
    ] = None,
    call_dangerous: Annotated[
        bool,
        typer.Option("--call-dangerous-tools", help="Also call tools that may change things. Use only in a sandbox."),
    ] = False,
    sandbox: Annotated[str | None, typer.Option("--sandbox", help="auto, docker, or process.")] = None,
    allow_host: Annotated[
        bool, typer.Option("--allow-host", help="Allow running servers on this machine without Docker.")
    ] = False,
    network: Annotated[
        str | None,
        typer.Option(
            "--network", help="Docker sandbox network: none, allow, or auto (only if the server needs the internet)."
        ),
    ] = None,
    source: Annotated[
        str | None, typer.Option("--source", help="Folder or file with the server's source code.")
    ] = None,
    env: Annotated[list[str] | None, typer.Option("--env", "-e", help="Extra server env, KEY=VALUE.")] = None,
    header: Annotated[
        list[str] | None, typer.Option("--header", "-H", help="Extra HTTP header, 'Name: value'.")
    ] = None,
    transport: Annotated[str | None, typer.Option("--transport", help="Force http or sse for URLs.")] = None,
    name: Annotated[str | None, typer.Option("--name", help="Name to show for this server.")] = None,
    rules: Annotated[
        list[str] | None, typer.Option("--rule", "-r", help="Only run these rules (IDs or prefixes like MCP-EXEC).")
    ] = None,
    disable_rule: Annotated[list[str] | None, typer.Option("--disable-rule", help="Skip these rules.")] = None,
    rules_dir: Annotated[list[str] | None, typer.Option("--rules-dir", help="Folder with YAML rules.")] = None,
    min_severity: Annotated[
        str | None, typer.Option("--min-severity", help="Hide findings below this severity.")
    ] = None,
    fail_on: Annotated[
        str | None, typer.Option("--fail-on", help="Exit 1 at or above this severity (or 'none').")
    ] = None,
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="console, json, markdown, sarif. Repeat for more.")
    ] = None,
    output: Annotated[str | None, typer.Option("--output", "-o", help="Folder for report files.")] = None,
    json_out: Annotated[
        bool, typer.Option("--json", help="Print the JSON report to stdout instead of the console view.")
    ] = False,
    ai: Annotated[bool | None, typer.Option("--ai/--no-ai", help="Ask an AI model for a second opinion.")] = None,
    ai_provider: Annotated[
        str | None, typer.Option("--ai-provider", help="openai, anthropic, xai, openrouter, or groq.")
    ] = None,
    ai_model: Annotated[str | None, typer.Option("--ai-model", help="Model name for the AI provider.")] = None,
    ai_setup: Annotated[
        str | None,
        typer.Option(
            "--ai-setup",
            help="With --run: let the AI work out how to start a repository. auto (when automatic setup fails), "
            "always, or never.",
        ),
    ] = None,
    no_pins: Annotated[bool, typer.Option("--no-pins", help="Do not compare or save tool pins.")] = False,
    update_pins: Annotated[
        bool, typer.Option("--update-pins", help="Accept changed tools and save their new pins.")
    ] = False,
    timeout: Annotated[float | None, typer.Option("--timeout", help="Hard time limit per server, in seconds.")] = None,
    startup_timeout: Annotated[
        float | None,
        typer.Option(
            "--startup-timeout", help="Seconds a server may take to start (default 60). Raise it for slow downloads."
        ),
    ] = None,
    no_connect: Annotated[
        bool,
        typer.Option(
            "--no-connect", help="Do not start or contact servers. Check config, source, and dependencies only."
        ),
    ] = False,
    run: Annotated[
        bool,
        typer.Option(
            "--run",
            help="For a repository link or folder: install and start the server in the Docker sandbox "
            "(default: only read its code).",
        ),
    ] = False,
    verbose: VerboseOpt = 0,
) -> None:
    """Scan MCP servers for security problems."""
    settings = load(config, verbose)
    options = ScanOptions(
        dynamic=dynamic,
        call_dangerous_tools=call_dangerous or None,
        ai=ai,
        ai_provider=ai_provider,
        ai_model=ai_model,
        ai_setup=ai_setup,
        min_severity=min_severity,
        fail_on=fail_on,
        formats=formats or [],
        output_dir=output,
        sandbox_mode=sandbox,
        allow_host=allow_host or None,
        network=network,
        rules_enabled=rules or [],
        rules_disabled=disable_rule or [],
        source=source,
        timeout=timeout,
        startup_timeout=startup_timeout,
        connect=False if no_connect else None,
    )
    try:
        settings = apply_options(settings, options)
    except ValueError as exc:
        fail(str(exc))
    if not target and not discover and not settings.servers:
        fail("Give a target (command, URL, repository link, folder, or file), or use --discover.")
    request = ScanRequest(
        target=TargetRequest(
            target=target,
            discover=discover,
            server_names=server or [],
            transport=transport,
            extra_env=parse_pairs(env, "env"),
            extra_headers=parse_pairs(header, "header"),
            source_path=source,
            name=name,
            run=run,
        ),
        rules_dirs=rules_dir or [],
        host_confirm=confirm_host,
        use_pins=not no_pins,
        update_pins=update_pins,
        progress=progress,
    )
    try:
        report = make_engine(settings).run(request)
    except ScannerError as exc:
        fail(str(exc))
    if json_out:
        print_json(report_to_dict(report))
    elif "console" in settings.output.formats or not settings.output.formats:
        ConsoleReporter(show_evidence=settings.output.show_evidence, verbose=verbose > 0).print(report, out)
    try:
        for path in write_reports(report, settings.output.formats, settings.output.directory):
            err.print(f"Wrote {path}")
    except OSError as exc:
        fail(f"Could not write a report: {exc}")
    raise typer.Exit(exit_code(report, settings.scan.fail_on))


@app.command()
def inspect(
    target: Annotated[str, typer.Argument(help="Command, URL, MCP config file, or tools file.")],
    server: Annotated[list[str] | None, typer.Option("--server", "-s")] = None,
    config: ConfigOpt = None,
    allow_host: Annotated[bool, typer.Option("--allow-host")] = False,
    sandbox: Annotated[str | None, typer.Option("--sandbox")] = None,
    transport: Annotated[str | None, typer.Option("--transport")] = None,
    header: Annotated[list[str] | None, typer.Option("--header", "-H")] = None,
    env: Annotated[list[str] | None, typer.Option("--env", "-e")] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    verbose: VerboseOpt = 0,
) -> None:
    """Connect and list tools, prompts, and resources. No security rules run."""
    settings = apply_options(load(config, verbose), ScanOptions(sandbox_mode=sandbox, allow_host=allow_host or None))
    settings.rules.disabled = ["*"]
    request = ScanRequest(
        target=TargetRequest(
            target=target,
            server_names=server or [],
            transport=transport,
            extra_headers=parse_pairs(header, "header"),
            extra_env=parse_pairs(env, "env"),
        ),
        host_confirm=confirm_host,
        use_pins=False,
        progress=progress,
    )
    try:
        report = make_engine(settings).run(request)
    except ScannerError as exc:
        fail(str(exc))
    if json_out:
        data = [
            {
                "server": s.server,
                "status": s.status.value,
                "inventory": s.inventory.model_dump(mode="json", exclude={"tools": {"__all__": {"raw"}}}),
            }
            for s in report.servers
        ]
        print_json(data)
        raise typer.Exit(exit_code(report, None))
    for result in report.servers:
        inv = result.inventory
        out.print(
            f"[bold]{result.name}[/] ({result.status.value}) {inv.server_name or ''} {inv.server_version or ''} protocol {inv.protocol_version or '?'}"
        )
        for error in result.errors:
            out.print(f"  [red]error ({error.stage}):[/] {error.message}")
        if inv.instructions:
            out.print(f"  Instructions: {inv.instructions[:300]}")
        table = Table("Tool", "Parameters", "Description", show_lines=False)
        for tool in inv.tools:
            params = ", ".join(f"{n}{'*' if n in tool.required() else ''}" for n in tool.properties())
            table.add_row(tool.name, params, tool.description[:120].replace("\n", " "))
        out.print(table)
        for prompt in inv.prompts:
            out.print(f"  prompt [cyan]{prompt.name}[/]: {prompt.description[:120]}")
        for resource in inv.resources:
            out.print(f"  resource [cyan]{resource.uri}[/]: {resource.description[:120]}")
    raise typer.Exit(exit_code(report, None))


@app.command()
def discover(
    json_out: Annotated[bool, typer.Option("--json")] = False,
    all_paths: Annotated[bool, typer.Option("--all", help="Also show paths that do not exist.")] = False,
) -> None:
    """List MCP client config files on this computer and the servers in them."""
    rows: list[dict[str, Any]] = []
    for known in known_config_paths():
        if not known.exists and not all_paths:
            continue
        servers: list[str] = []
        problem = None
        if known.exists:
            try:
                servers = [s.name for s in parse_client_config(known.path)]
            except ScannerError as exc:
                problem = str(exc)
        rows.append(
            {
                "client": known.client,
                "path": str(known.path),
                "exists": known.exists,
                "servers": servers,
                "error": problem,
            }
        )
    if json_out:
        print_json(rows)
        return
    if not rows:
        out.print("No MCP client config files found.")
        return
    table = Table("Client", "Config file", "Servers")
    for row in rows:
        servers_text = ", ".join(row["servers"]) or ("[red]" + row["error"] + "[/]" if row["error"] else "-")
        table.add_row(row["client"], row["path"] + ("" if row["exists"] else " (missing)"), servers_text)
    out.print(table)
    out.print("Scan them all with: mcp-scanner scan --discover")


@app.command()
def report(
    file: Annotated[Path, typer.Argument(help="A JSON report written by this scanner.")],
    formats: Annotated[list[str] | None, typer.Option("--format", "-f", help="console, json, markdown, sarif.")] = None,
    output: Annotated[str | None, typer.Option("--output", "-o", help="Folder for report files.")] = None,
) -> None:
    """Turn a saved JSON report into other formats."""
    try:
        data = load_report(file)
    except (OSError, ValueError) as exc:
        fail(f"Could not read {file}: {exc}")
    chosen = formats or ["console"]
    for name in chosen:
        if name not in REPORTERS:
            fail(f"Unknown format '{name}'. Use: {', '.join(REPORTERS)}")
    if "console" in chosen:
        ConsoleReporter().print(data, out)
    for name in chosen:
        if name == "console":
            continue
        if output is None:
            out.print(get_reporter(name).render(data))
    if output:
        for path in write_reports(data, chosen, output):
            err.print(f"Wrote {path}")


@app.command()
def version() -> None:
    """Show the scanner version, its license, and whether this is an official build."""
    info = product_info()
    out.print(f"{PRODUCT_NAME} {__version__}. {COPYRIGHT}.")
    out.print(info.license_notice)
    out.print(f"Build: {info.build}" + (f" ({info.build_notice})" if info.build_notice else ""))


def main() -> None:
    # Windows consoles often use a code page that cannot show every character a server sends
    # (arrows, emoji, other scripts). Show "?" for those instead of crashing the report.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):
                pass
    try:
        app()
    except KeyboardInterrupt:
        err.print("Stopped.")
        raise SystemExit(EXIT_ERROR) from None
