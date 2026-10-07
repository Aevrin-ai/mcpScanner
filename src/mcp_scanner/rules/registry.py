# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Find, select, and run rules.

Rules come from three places:
  1. built-in rules in `mcp_scanner/rules/builtin/` (found automatically)
  2. plugins that expose rules through the `aevrin_mcp_scanner.rules` entry point
  3. YAML rule files from folders given with --rules-dir or `rules.rules_dirs`

A crash in one rule is recorded as a scan error. The other rules keep running.
"""

from __future__ import annotations

import fnmatch
import importlib
import inspect
import logging
import pkgutil
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib.metadata import entry_points

from mcp_scanner.config.settings import RuleSettings
from mcp_scanner.core.errors import ConfigError
from mcp_scanner.models.finding import FindingCandidate
from mcp_scanner.models.result import ScanError
from mcp_scanner.rules.base import Rule
from mcp_scanner.rules.yaml_rules import load_yaml_rules
from mcp_scanner.scanner.context import ScanContext

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "aevrin_mcp_scanner.rules"


def builtin_rules() -> list[Rule]:
    from mcp_scanner.rules import builtin

    rules: list[Rule] = []
    for module_info in sorted(pkgutil.iter_modules(builtin.__path__), key=lambda m: m.name):
        module = importlib.import_module(f"{builtin.__name__}.{module_info.name}")
        rules.extend(_rules_in(module))
    return rules


def _rules_in(module: object) -> list[Rule]:
    found = []
    for _, value in inspect.getmembers(module, inspect.isclass):
        if (
            issubclass(value, Rule)
            and value is not Rule
            and value.id
            and value.__module__ == getattr(module, "__name__", None)
        ):
            found.append(value())
    return found


def plugin_rules() -> list[Rule]:
    """Rules from installed plugins. A broken plugin is logged and skipped."""
    rules: list[Rule] = []
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            loaded = ep.load()
        except Exception as exc:
            log.warning("Could not load rule plugin %s: %s", ep.name, exc)
            continue
        items = loaded() if callable(loaded) and not inspect.isclass(loaded) else loaded
        for item in items if isinstance(items, list | tuple) else [items]:
            rule = item() if inspect.isclass(item) else item
            if isinstance(rule, Rule) and rule.id:
                rule.origin = f"plugin ({ep.name})"  # type: ignore[misc]
                rules.append(rule)
    return rules


def id_matches(rule_id: str, patterns: Iterable[str]) -> bool:
    """'MCP-EXEC-001', 'MCP-EXEC-*', and 'MCP-EXEC' all select MCP-EXEC-001."""
    rid = rule_id.upper()
    for raw in patterns:
        pattern = raw.strip().upper()
        if not pattern:
            continue
        if fnmatch.fnmatchcase(rid, pattern) or rid.startswith(pattern.rstrip("-") + "-"):
            return True
    return False


@dataclass
class RuleRun:
    candidates: list[FindingCandidate] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    rules_run: list[str] = field(default_factory=list)
    rules_skipped: dict[str, str] = field(default_factory=dict)


class RuleRegistry:
    def __init__(self, rules: list[Rule]) -> None:
        seen: dict[str, Rule] = {}
        for rule in rules:
            if rule.id in seen:
                # A later rule (YAML or plugin) replaces a built-in one with the same ID.
                log.info("Rule %s from %s replaces the earlier one", rule.id, rule.origin)
            seen[rule.id] = rule
        self._rules = seen

    @classmethod
    def load(cls, settings: RuleSettings | None = None, extra_dirs: Iterable[str] = ()) -> RuleRegistry:
        rules = builtin_rules() + plugin_rules()
        dirs = [*(settings.rules_dirs if settings else []), *extra_dirs]
        for folder in dirs:
            rules.extend(load_yaml_rules(folder))
        return cls(rules)

    def all(self) -> list[Rule]:
        return sorted(self._rules.values(), key=lambda r: r.id)

    def get(self, rule_id: str) -> Rule | None:
        return self._rules.get(rule_id) or self._rules.get(rule_id.upper())

    def select(self, enabled: Iterable[str] = (), disabled: Iterable[str] = ()) -> list[Rule]:
        enabled, disabled = list(enabled), list(disabled)
        chosen = [r for r in self.all() if not enabled or id_matches(r.id, enabled)]
        chosen = [r for r in chosen if not id_matches(r.id, disabled)]
        if enabled and not chosen:
            raise ConfigError(f"No rule matches: {', '.join(enabled)}. See `mcp-scanner rules list`.")
        return chosen

    def run(self, ctx: ScanContext, rules: list[Rule], settings: RuleSettings | None = None) -> RuleRun:
        result = RuleRun()
        overrides = {k.upper(): v for k, v in (settings.severity_overrides if settings else {}).items()}
        for rule in rules:
            reason = rule.can_run(ctx)
            if reason:
                result.rules_skipped[rule.id] = reason
                continue
            try:
                found = list(rule.check(ctx))
            except Exception as exc:
                log.debug("Rule %s failed", rule.id, exc_info=True)
                result.errors.append(
                    ScanError(stage="rules", message=f"Rule {rule.id} failed: {type(exc).__name__}: {exc}")
                )
                continue
            result.rules_run.append(rule.id)
            for candidate in found:
                if rule.id.upper() in overrides:
                    candidate.severity = overrides[rule.id.upper()]
                result.candidates.append(candidate)
        return result
