# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Small timing helpers."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager


class Deadline:
    """A point in time after which work should stop."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self._end = time.monotonic() + seconds

    @property
    def remaining(self) -> float:
        return max(0.0, self._end - time.monotonic())

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self._end

    def cap(self, timeout: float) -> float:
        """A timeout that never goes past the deadline (but at least one second)."""
        return max(1.0, min(timeout, self.remaining))


@contextmanager
def stage_timer(store: dict[str, float], name: str) -> Iterator[None]:
    """Add the time spent in the block to store[name]."""
    start = time.perf_counter()
    try:
        yield
    finally:
        store[name] = round(store.get(name, 0.0) + time.perf_counter() - start, 3)
