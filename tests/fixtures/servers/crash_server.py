"""Hostile fixture: prints an error and exits at once."""

import sys

print("fatal: could not load config file", file=sys.stderr)
sys.exit(3)
