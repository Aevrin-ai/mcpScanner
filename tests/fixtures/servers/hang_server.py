"""Hostile fixture: starts, reads input, and never answers."""

import sys
import time

for _ in sys.stdin:
    time.sleep(3600)
