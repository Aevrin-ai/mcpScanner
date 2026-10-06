# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""A throwaway folder for one server run.

The server gets its own home, temp, and work folders inside this workspace.
After the scan we compare the files to see what the server wrote, then delete everything.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import time
from pathlib import Path

from mcp_scanner.sandbox.canary import CanarySet, decoy_files

log = logging.getLogger(__name__)

# Package manager caches. Servers started with npx or uvx fill these with thousands of
# files, which say nothing about the server. They are left out of "files written".
CACHE_PREFIXES = (
    "home/.npm/",
    "home/.cache/",
    "home/.local/share/uv/",
    "home/.local/share/pnpm/",
    "home/AppData/Local/npm-cache/",
    "home/AppData/Local/uv/",
    "home/.yarn/",
    "home/.bun/install/",
    "deps/",  # installed by the separate install step, before the server ran
    "tmp/node-compile-cache/",
    "home/.npm/_logs/",
)


class Workspace:
    def __init__(self, canary: CanarySet, *, with_decoys: bool = True, keep: bool = False) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="aevrin-scan-"))
        self.home = self.root / "home"
        self.tmp = self.root / "tmp"
        self.work = self.root / "work"
        self.keep = keep
        for folder in (self.home, self.tmp, self.work):
            folder.mkdir(parents=True, exist_ok=True)
        if with_decoys:
            for rel_path, content in decoy_files(canary).items():
                target = self.home / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
        self._before = self._snapshot()

    def _snapshot(self) -> dict[str, tuple[float, int]]:
        state: dict[str, tuple[float, int]] = {}
        for path in self.root.rglob("*"):
            try:
                if path.is_file():
                    stat = path.stat()
                    state[path.relative_to(self.root).as_posix()] = (stat.st_mtime, stat.st_size)
            except OSError:
                continue
        return state

    def changed_files(self, ignore_prefixes: tuple[str, ...] = ()) -> list[str]:
        """Files the server created or changed, relative to the workspace."""
        after = self._snapshot()
        changed = [
            path
            for path, meta in after.items()
            if self._before.get(path) != meta and not path.startswith(ignore_prefixes)
        ]
        return sorted(changed)

    def cleanup(self) -> None:
        if self.keep:
            log.info("Keeping workspace at %s", self.root)
            return
        # On Windows a file can stay locked for a moment after the process dies.
        for attempt in range(5):
            shutil.rmtree(self.root, ignore_errors=True)
            if not self.root.exists():
                return
            time.sleep(0.2 * (attempt + 1))
        log.warning("Could not fully delete workspace %s", self.root)
