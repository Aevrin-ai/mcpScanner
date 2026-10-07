# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Log setup. Logs go to stderr (or a file) and secrets are removed from every message."""

from __future__ import annotations

import json
import logging
import sys

from mcp_scanner.config.settings import LoggingSettings
from mcp_scanner.utils.secrets import redact


class RedactingFilter(logging.Filter):
    """Hide secrets in log messages, whatever code logged them."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            return True
        record.msg = redact(message)
        record.args = None
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "time": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            data["error"] = self.formatException(record.exc_info)
        return json.dumps(data)


def configure_logging(settings: LoggingSettings, verbose: int = 0) -> None:
    level = logging.DEBUG if verbose >= 2 else logging.INFO if verbose == 1 else getattr(logging, settings.level)
    handler: logging.Handler = (
        logging.FileHandler(settings.file, encoding="utf-8") if settings.file else logging.StreamHandler(sys.stderr)
    )
    handler.setFormatter(
        JsonFormatter() if settings.json_format else logging.Formatter("%(levelname)s %(name)s: %(message)s")
    )
    handler.addFilter(RedactingFilter())
    root = logging.getLogger("mcp_scanner")
    root.handlers[:] = [handler]
    root.setLevel(level)
    root.propagate = False
    # Third party libraries are noisy at INFO.
    for name in ("httpx", "httpcore", "openai", "anthropic", "grpc"):
        logging.getLogger(name).setLevel(logging.WARNING)
