"""Allow/deny policy configuration for organization-specific scanner decisions."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Finding, StaticCandidate


class PolicyConfigurationError(ValueError):
    """A policy file is unreadable or violates the documented schema."""


@dataclass(frozen=True)
class PolicySelector:
    rule_id: str | None = None
    subject_pattern: str | None = None

    @classmethod
    def from_value(cls, value: str | dict[str, Any]) -> PolicySelector:
        if isinstance(value, str):
            return cls(rule_id=value)
        if not isinstance(value, dict):
            raise PolicyConfigurationError(
                "Policy selectors must be a rule ID string or an object."
            )
        rule_id = value.get("rule_id")
        subject_pattern = value.get("subject_pattern")
        if rule_id is None and subject_pattern is None:
            raise PolicyConfigurationError("A policy selector needs rule_id or subject_pattern.")
        if rule_id is not None and not isinstance(rule_id, str):
            raise PolicyConfigurationError("Policy selector rule_id must be a string.")
        if subject_pattern is not None:
            if not isinstance(subject_pattern, str):
                raise PolicyConfigurationError("Policy selector subject_pattern must be a string.")
            try:
                re.compile(subject_pattern)
            except re.error as error:
                raise PolicyConfigurationError(
                    f"Invalid policy subject_pattern {subject_pattern!r}: {error}"
                ) from error
        return cls(rule_id=rule_id, subject_pattern=subject_pattern)

    def matches(self, candidate: StaticCandidate) -> bool:
        if self.rule_id is not None and self.rule_id != candidate.rule_id:
            return False
        return self.subject_pattern is None or bool(
            re.search(self.subject_pattern, candidate.descriptor.name)
        )


@dataclass(frozen=True)
class ScanPolicy:
    allow: tuple[PolicySelector, ...] = ()
    deny: tuple[PolicySelector, ...] = ()
    semantic_threshold: float | None = None

    def allows(self, candidate: StaticCandidate) -> bool:
        return any(selector.matches(candidate) for selector in self.allow)

    def denies(self, candidate: StaticCandidate) -> bool:
        return any(selector.matches(candidate) for selector in self.deny)

    def finding_for_denial(self, candidate: StaticCandidate) -> Finding:
        return Finding(
            rule_id=candidate.rule_id,
            title=candidate.title,
            category=candidate.category,
            severity=candidate.severity,
            message=candidate.description,
            subject_kind=candidate.descriptor.kind,
            subject_name=candidate.descriptor.name,
            evidence=candidate.evidence,
            confidence=1.0,
            layers=("static", "policy"),
            rationale=(
                "An explicit MCPSentinel policy deny selector requires this finding to be reported."
            ),
        )


def load_policy(path: Path | None) -> ScanPolicy:
    if path is None:
        return ScanPolicy()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise PolicyConfigurationError(f"Could not read policy {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise PolicyConfigurationError(f"Policy {path} is not valid JSON: {error}") from error
    if not isinstance(raw, dict):
        raise PolicyConfigurationError("Policy must be a JSON object.")
    unknown = set(raw) - {"allow", "deny", "semantic_threshold"}
    if unknown:
        raise PolicyConfigurationError(f"Unknown policy keys: {', '.join(sorted(unknown))}")
    allow = _selectors(raw.get("allow", []), "allow")
    deny = _selectors(raw.get("deny", []), "deny")
    threshold = raw.get("semantic_threshold")
    if threshold is not None and (
        not isinstance(threshold, (int, float)) or not 0 <= threshold <= 1
    ):
        raise PolicyConfigurationError("policy semantic_threshold must be a number from 0 to 1.")
    return ScanPolicy(allow=allow, deny=deny, semantic_threshold=threshold)


def _selectors(raw: Any, key: str) -> tuple[PolicySelector, ...]:
    if not isinstance(raw, list):
        raise PolicyConfigurationError(f"Policy {key} must be an array.")
    return tuple(PolicySelector.from_value(value) for value in raw)
