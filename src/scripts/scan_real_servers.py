# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Scan a list of real, public MCP servers and print a short summary.

Usage:
    python src/scripts/scan_real_servers.py [--dynamic] [--allow-host] [--output DIR]

The servers are downloaded with npx and uvx, so this needs network access.
Without Docker they run on this machine with the process sandbox, so --allow-host
is required. Only use it with servers you are willing to run.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# (name, command). {tmp} is replaced with a throwaway folder.
SERVERS = [
    ("everything", "npx -y @modelcontextprotocol/server-everything@2026.8.31"),
    ("filesystem", "npx -y @modelcontextprotocol/server-filesystem@2026.8.31 {tmp}"),
    ("memory", "npx -y @modelcontextprotocol/server-memory@2026.8.31"),
    ("sequential-thinking", "npx -y @modelcontextprotocol/server-sequential-thinking@2026.8.31"),
    ("time", "uvx mcp-server-time==2026.8.18"),
    ("fetch", "uvx mcp-server-fetch==2026.8.18"),
    ("git", "uvx mcp-server-git==2026.8.18 --repository {repo}"),
    ("playwright", "npx -y @playwright/mcp@0.0.83 --headless"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dynamic", action="store_true")
    parser.add_argument("--allow-host", action="store_true")
    parser.add_argument("--output", default="reports/real-servers")
    parser.add_argument("--only", nargs="*", default=[])
    args = parser.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="aevrin-real-"))
    repo = tmp / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=False)
    rows = []
    for name, template in SERVERS:
        if args.only and name not in args.only:
            continue
        command = template.format(tmp=tmp.as_posix(), repo=repo.as_posix())
        cmd = [
            sys.executable,
            "-m",
            "mcp_scanner",
            "scan",
            command,
            "--name",
            name,
            "--json",
            "--no-pins",
            "--fail-on",
            "none",
            "--timeout",
            "300",
        ]
        if args.dynamic:
            cmd.append("--dynamic")
        if args.allow_host:
            cmd.append("--allow-host")
        start = time.monotonic()
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900, check=False)
        seconds = round(time.monotonic() - start, 1)
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            rows.append({"server": name, "error": proc.stderr.strip()[-300:], "seconds": seconds})
            continue
        (out / f"{name}.json").write_text(proc.stdout, encoding="utf-8")
        server = report["servers"][0]
        active = [f for f in server["findings"] if f["validation_status"] in ("confirmed", "validated", "unverified")]
        rows.append(
            {
                "server": name,
                "status": server["status"],
                "grade": server["risk"]["grade"],
                "score": server["risk"]["score"],
                "tools": len(server["inventory"]["tools"]),
                "findings": {f["rule_id"]: f["severity"] for f in active},
                "errors": [e["message"][:160] for e in server["errors"]],
                "seconds": seconds,
            }
        )
    (out / "summary.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    for row in rows:
        print(json.dumps(row))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
