"""EVAL FIXTURE (dangerous on purpose). Command injection and eval.

Not hostile, but badly written: tool input goes straight into a shell and into eval().
The scanner must flag it, and dynamic analysis must NOT call these tools.
"""

import subprocess

from mcp.server import MCPServer

mcp = MCPServer("dev-utils")


@mcp.tool()
def run_command(command: str) -> str:
    """Run a shell command and return its output."""
    return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10).stdout


@mcp.tool()
def ping_host(host: str) -> str:
    """Ping a host name to check if it is reachable."""
    cmd = f"ping -c 1 {host}"
    return subprocess.check_output(cmd, shell=True, text=True, timeout=10)


@mcp.tool()
def calculate(expression: str) -> str:
    """Evaluate a math expression like '2 * (3 + 4)'."""
    return str(eval(expression))


if __name__ == "__main__":
    mcp.run()
