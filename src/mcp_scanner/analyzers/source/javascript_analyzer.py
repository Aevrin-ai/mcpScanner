# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Pattern based checks for JavaScript and TypeScript MCP servers.

We do not build a full syntax tree for JavaScript. That would need a large
parser dependency. Line patterns catch the most common dangerous calls. The
results get lower confidence than the Python analysis.
"""

from __future__ import annotations

import re

from mcp_scanner.analyzers.source import facts as f
from mcp_scanner.rules.patterns import SENSITIVE_PATH, SUSPICIOUS_DOMAINS

MCP_MARKERS = re.compile(
    r"@modelcontextprotocol/sdk|\bMcpServer\b|registerTool\s*\(|\.tool\s*\(\s*['\"]|ListToolsRequestSchema"
)
CHILD_PROCESS = re.compile(
    r"""require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]"""
)
TOOL_REGISTRATION = re.compile(r"""(?:registerTool|\.tool|addTool)\s*\(\s*['"]([\w.\-]+)['"]""")

# Line patterns: (category, regex, detail).
LINE_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        f.OBFUSCATED_EXEC,
        re.compile(r"\b(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent)\s*\("),
        "runs code decoded at run time",
    ),
    (f.CODE_EVAL, re.compile(r"(?<![.\w$])eval\s*\(\s*(?!['\"`][^'\"`]*['\"`]\s*\))"), "eval() of a dynamic value"),
    (f.CODE_EVAL, re.compile(r"\bnew\s+Function\s*\("), "new Function()"),
    (
        f.CODE_EVAL,
        re.compile(r"\bvm\.(?:runInThisContext|runInNewContext|runInContext|compileFunction)\s*\("),
        "node vm module",
    ),
    (
        f.FILE_WRITE,
        re.compile(
            r"\bfs(?:\.promises)?\.(?:writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|rename|renameSync)\s*\(\s*(?!['\"`])"
        ),
        "writes or deletes a file from a variable path",
    ),
    (
        f.FILE_READ,
        re.compile(
            r"\bfs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|readdir|readdirSync)\s*\(\s*(?!['\"`])"
        ),
        "reads a file from a variable path",
    ),
    (f.NETWORK, re.compile(r"(?<![.\w$])fetch\s*\(\s*(?!['\"])"), "fetch() with a variable URL"),
    (
        f.NETWORK,
        re.compile(r"\baxios(?:\.(?:get|post|put|patch|delete|request))?\s*\(\s*(?!['\"])"),
        "axios call with a variable URL",
    ),
    (
        f.ENV_DUMP,
        re.compile(r"JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:entries|keys|values)\(\s*process\.env\s*\)"),
        "reads the whole environment",
    ),
)
SHELL_EXEC = re.compile(r"(?:(?<![.\w$])|child_process\.|cp\.|childProcess\.)(?:exec|execSync)\s*\(")
SPAWN = re.compile(r"(?:(?<![.\w$])|child_process\.|cp\.|childProcess\.)(?:spawn|spawnSync|execFile|execFileSync)\s*\(")
# Lines longer than this are minified code. They are only checked for secrets.
LONG_LINE = 500
DYNAMIC_ARG = re.compile(r"\$\{|\+\s*\w|\w\s*\+")


def analyze_javascript(text: str, rel_path: str) -> tuple[list[f.ToolFunction], list[f.CodeHit], bool]:
    lines = text.splitlines()
    has_child_process = bool(CHILD_PROCESS.search(text))
    tools = [
        f.ToolFunction(m.group(1), m.group(1), rel_path, text.count("\n", 0, m.start()) + 1)
        for m in TOOL_REGISTRATION.finditer(text)
    ]
    hits: list[f.CodeHit] = []
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith(("//", "*", "/*")) or len(stripped) > LONG_LINE:
            # Hand written code is never this wide. Such lines are minified bundles, where the
            # patterns match by accident and the evidence cannot be read.
            continue
        hits.extend(_line_hits(stripped, number, rel_path, has_child_process))
    return tools, hits, bool(MCP_MARKERS.search(text))


def _line_hits(line: str, number: int, rel_path: str, has_child_process: bool) -> list[f.CodeHit]:
    hits: list[f.CodeHit] = []

    def add(category: str, detail: str, dynamic: bool = False) -> None:
        hits.append(f.CodeHit(category, rel_path, number, line[:200], "javascript", detail=detail, tainted=dynamic))

    if has_child_process and SHELL_EXEC.search(line):
        add(f.COMMAND, "runs through a shell (exec)", bool(DYNAMIC_ARG.search(line)))
    elif has_child_process and SPAWN.search(line):
        shell = "shell: true" in line.replace(" ", "").replace("shell:true", "shell: true")
        add(f.COMMAND, "runs through a shell" if shell else "runs a program", bool(DYNAMIC_ARG.search(line)) and shell)
    for category, regex, detail in LINE_PATTERNS:
        if regex.search(line):
            add(category, detail, category in (f.FILE_WRITE, f.FILE_READ, f.NETWORK) and bool(DYNAMIC_ARG.search(line)))
            if category == f.OBFUSCATED_EXEC:
                break
    for literal in re.findall(r"""['"`]([^'"`]{4,200})['"`]""", line):
        if SENSITIVE_PATH.search(literal):
            add(f.SENSITIVE_PATH, f"mentions '{literal[:80]}'")
        if SUSPICIOUS_DOMAINS.search(literal):
            add(f.EXFIL_ENDPOINT, f"hardcoded destination '{literal[:80]}'")
    return _dedupe_eval(hits)


def _dedupe_eval(hits: list[f.CodeHit]) -> list[f.CodeHit]:
    """An obfuscated eval is also an eval. Keep only the stronger one."""
    if any(h.category == f.OBFUSCATED_EXEC for h in hits):
        return [h for h in hits if h.category != f.CODE_EVAL]
    return hits
