# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Write docs/rules.md from the rule registry, so the docs always match the code.

Usage:  python src/scripts/gen_rules_doc.py
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from mcp_scanner.rules.registry import builtin_rules

GROUPS = {
    "INJ": "Prompt injection",
    "POISON": "Tool poisoning",
    "SHADOW": "Tool shadowing",
    "EXEC": "Command and code execution",
    "FS": "File system",
    "NET": "Network",
    "SQL": "SQL",
    "SECRET": "Secrets",
    "PRIV": "Privilege",
    "SCOPE": "Scope",
    "PERM": "Permissions",
    "CFG": "Configuration",
    "AUTH": "Authentication",
    "SRC": "Source code",
    "DEP": "Dependencies",
    "DYN": "Runtime behavior",
    "PROTO": "Protocol",
    "QUALITY": "Quality",
}


def main() -> None:
    rules = sorted(builtin_rules(), key=lambda r: r.id)
    groups: dict[str, list] = defaultdict(list)
    for rule in rules:
        groups[rule.id.split("-")[1]].append(rule)
    lines = [
        "# Rules",
        "",
        "This page is made by `src/scripts/gen_rules_doc.py`. Do not edit it by hand.",
        "",
        f"There are {len(rules)} built-in rules. List them with `mcp-scanner rules list`, and explain one with",
        "`mcp-scanner rules show MCP-POISON-001`.",
        "",
        '"Needs" tells you what a rule must have to run: `source` (the server code, from `--source` or the launch',
        "command), `dynamic` (`--dynamic`). Rules without needs run on every scan.",
        "",
        "| ID | Severity | Title | Needs |",
        "|---|---|---|---|",
    ]
    for rule in rules:
        lines.append(
            f"| [{rule.id}](#{rule.id.lower()}) | {rule.severity.value} | {rule.title} | {', '.join(sorted(rule.needs)) or '-'} |"
        )
    for key, title in GROUPS.items():
        if key not in groups:
            continue
        lines += ["", f"## {title}"]
        for rule in groups[key]:
            lines += [
                "",
                f"### {rule.id}",
                "",
                f"**{rule.title}** (default severity: {rule.severity.value}, category: {rule.category.value})",
                "",
                f"- What it checks: {rule.description}",
            ]
            if rule.why_it_matters:
                lines.append(f"- Why it matters: {rule.why_it_matters}")
            if rule.attack_scenario:
                lines.append(f"- Example: {rule.attack_scenario}")
            lines.append(f"- How to fix: {rule.recommendation}")
            for ref in rule.references:
                lines.append(f"- Reference: <{ref}>")
    out = Path(__file__).resolve().parents[2] / "docs" / "rules.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out} ({len(rules)} rules)")


if __name__ == "__main__":
    main()
