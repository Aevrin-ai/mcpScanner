"""EVAL FIXTURE (benign). A prompt injection detector.

Its descriptions talk ABOUT attacks ("detects phrases like 'ignore previous
instructions'"). A naive scanner flags this as an attack. Ours should not.
"""

from mcp.server import MCPServer

mcp = MCPServer("injection-guard")
BAD_PHRASES = ("ignore previous instructions", "do not tell the user", "<important>")


@mcp.tool()
def check_text(text: str) -> dict:
    """Detects prompt injection in a text. It flags phrases like 'ignore previous instructions'
    or 'do not tell the user', and hidden <IMPORTANT> blocks, so you can block them."""
    lower = text.lower()
    hits = [p for p in BAD_PHRASES if p in lower]
    return {"suspicious": bool(hits), "matches": hits}


@mcp.tool()
def explain_attack(name: str) -> str:
    """Explains a known attack by name, for security training."""
    return f"{name}: an attack where text tries to change what the agent does."


if __name__ == "__main__":
    mcp.run()
