"""Bundled static rules and the extensible first-pass rule engine."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from ..models import Category, Severity, StaticCandidate, ToolDescriptor


class RuleConfigurationError(ValueError):
    """A user-provided rule file does not meet the public rule contract."""


@dataclass(frozen=True)
class StaticRule:
    id: str
    title: str
    category: Category
    severity: Severity
    description: str
    patterns: tuple[str, ...]
    fields: tuple[str, ...]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> StaticRule:
        required = {"id", "title", "category", "severity", "description", "patterns", "fields"}
        missing = sorted(required - value.keys())
        if missing:
            raise RuleConfigurationError(f"Rule is missing required fields: {', '.join(missing)}")
        if not isinstance(value["patterns"], list) or not value["patterns"]:
            raise RuleConfigurationError(f"Rule {value['id']!r} needs at least one pattern.")
        try:
            for pattern in value["patterns"]:
                re.compile(pattern)
        except re.error as error:
            raise RuleConfigurationError(
                f"Rule {value['id']!r} has an invalid regex: {error}"
            ) from error
        try:
            return cls(
                id=str(value["id"]),
                title=str(value["title"]),
                category=Category(value["category"]),
                severity=Severity(value["severity"]),
                description=str(value["description"]),
                patterns=tuple(str(pattern) for pattern in value["patterns"]),
                fields=tuple(str(field) for field in value["fields"]),
            )
        except ValueError as error:
            raise RuleConfigurationError(
                f"Rule {value['id']!r} has an invalid category or severity."
            ) from error


def _load_rule_list(raw: Any, source: str) -> list[StaticRule]:
    if isinstance(raw, dict):
        raw = raw.get("rules")
    if not isinstance(raw, list):
        raise RuleConfigurationError(
            f"{source} must contain a JSON array, or an object with a 'rules' array."
        )
    rules = [StaticRule.from_dict(item) for item in raw]
    duplicate_ids = {rule.id for rule in rules if sum(item.id == rule.id for item in rules) > 1}
    if duplicate_ids:
        raise RuleConfigurationError(
            f"{source} defines duplicate IDs: {', '.join(sorted(duplicate_ids))}"
        )
    return rules


def load_rules(extra_path: Path | None = None) -> list[StaticRule]:
    default_file = resources.files(__package__).joinpath("default.json")
    defaults = _load_rule_list(
        json.loads(default_file.read_text(encoding="utf-8")), "built-in rules"
    )
    if extra_path is None:
        return defaults
    try:
        additional = _load_rule_list(
            json.loads(extra_path.read_text(encoding="utf-8")), str(extra_path)
        )
    except OSError as error:
        raise RuleConfigurationError(
            f"Could not read custom rules {extra_path}: {error}"
        ) from error
    default_ids = {rule.id for rule in defaults}
    overlaps = sorted(default_ids & {rule.id for rule in additional})
    if overlaps:
        raise RuleConfigurationError(
            f"Custom rules cannot replace built-in IDs: {', '.join(overlaps)}"
        )
    return [*defaults, *additional]


def _searchable_fields(descriptor: ToolDescriptor) -> dict[str, str]:
    return {
        "name": descriptor.name,
        "description": descriptor.description,
        "schema": json.dumps(descriptor.schema, sort_keys=True),
        "metadata": json.dumps(descriptor.metadata, sort_keys=True),
    }


def _evidence(match: re.Match[str], field: str) -> str:
    start = max(0, match.start() - 55)
    end = min(len(match.string), match.end() + 55)
    snippet = " ".join(match.string[start:end].split())
    return f"{field} matched /{match.re.pattern}/: {snippet!r}"


class StaticAnalyzer:
    def __init__(self, rules: list[StaticRule]) -> None:
        self.rules = rules

    def analyze(self, descriptors: list[ToolDescriptor]) -> list[StaticCandidate]:
        candidates: list[StaticCandidate] = []
        for descriptor in descriptors:
            fields = _searchable_fields(descriptor)
            for rule in self.rules:
                evidence: list[str] = []
                for field in rule.fields:
                    text = fields.get(field, "")
                    for pattern in rule.patterns:
                        match = re.search(pattern, text, flags=re.IGNORECASE)
                        if match:
                            evidence.append(_evidence(match, field))
                if evidence:
                    candidates.append(
                        StaticCandidate(
                            rule_id=rule.id,
                            title=rule.title,
                            category=rule.category,
                            severity=rule.severity,
                            description=rule.description,
                            descriptor=descriptor,
                            evidence=tuple(evidence),
                        )
                    )
        return candidates
