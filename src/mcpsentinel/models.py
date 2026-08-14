"""Domain types shared across discovery, analysis, baselining, and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(type(self)).index(self)


class Category(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    TOOL_POISONING = "tool_poisoning"
    TOOL_SHADOWING = "tool_shadowing"
    SSRF = "ssrf"
    SECRET_EXFILTRATION = "secret_exfiltration"
    COMMAND_EXECUTION = "command_execution"
    DESTRUCTIVE_OPERATION = "destructive_operation"
    CROSS_SERVER_ATTACK = "cross_server_attack"
    OAUTH_CONFUSED_DEPUTY = "oauth_confused_deputy"
    RUG_PULL = "rug_pull"


class DescriptorKind(StrEnum):
    TOOL = "tool"
    PROMPT = "prompt"
    RESOURCE = "resource"
    RESOURCE_TEMPLATE = "resource_template"


class DynamicStatus(StrEnum):
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class TargetConfig:
    """A normalized, metadata-only MCP connection target."""

    transport: str
    identity: str
    url: str | None = None
    command: str | None = None
    arguments: tuple[str, ...] = ()
    environment: dict[str, str] = field(default_factory=dict)
    restrict_to_public_network: bool = False


@dataclass(frozen=True)
class ToolDescriptor:
    """A serializable MCP object definition, never an invocation result."""

    kind: DescriptorKind
    name: str
    description: str
    schema: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.name}"


@dataclass(frozen=True)
class StaticCandidate:
    rule_id: str
    title: str
    category: Category
    severity: Severity
    description: str
    descriptor: ToolDescriptor
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class JudgeVerdict:
    label: str
    confidence: float
    rationale: str
    judge: str
    cache_hit: bool = False

    @property
    def should_report(self) -> bool:
        return self.label in {"suspicious", "unsafe"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    category: Category
    severity: Severity
    message: str
    subject_kind: DescriptorKind
    subject_name: str
    evidence: tuple[str, ...]
    confidence: float
    layers: tuple[str, ...]
    rationale: str | None = None


@dataclass(frozen=True)
class DynamicObservation:
    """Sanitized record of an explicit tool call in the Docker sandbox."""

    tool_name: str
    status: DynamicStatus
    duration_ms: int
    response_digest: str | None = None
    content_types: tuple[str, ...] = ()
    process_count_before: int | None = None
    process_count_after: int | None = None
    filesystem_change_count: int | None = None
    detail: str | None = None


@dataclass
class ScanReport:
    target: TargetConfig
    descriptors: list[ToolDescriptor]
    findings: list[Finding]
    started_at: datetime
    completed_at: datetime | None = None
    judge: str = "heuristic"
    scan_version: str = "0.5.0"
    discovery_metadata: dict[str, Any] = field(default_factory=dict)
    dynamic_observations: list[DynamicObservation] = field(default_factory=list)
    baseline_state: str = "not_checked"
    baseline_updated: bool = False
    notices: list[str] = field(default_factory=list)

    def complete(self) -> None:
        self.completed_at = datetime.now(UTC)

    @property
    def counts(self) -> dict[str, int]:
        return {
            severity.value: sum(f.severity == severity for f in self.findings)
            for severity in Severity
        }

    @property
    def risk_score(self) -> int:
        weights = {
            Severity.INFO: 5,
            Severity.LOW: 20,
            Severity.MEDIUM: 45,
            Severity.HIGH: 75,
            Severity.CRITICAL: 100,
        }
        score = sum(weights[finding.severity] * finding.confidence for finding in self.findings)
        return min(100, round(score))

    @property
    def risk_level(self) -> Severity:
        score = self.risk_score
        if score >= 90:
            return Severity.CRITICAL
        if score >= 65:
            return Severity.HIGH
        if score >= 35:
            return Severity.MEDIUM
        if score > 0:
            return Severity.LOW
        return Severity.INFO


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_primitive(value: Any) -> Any:
    """Convert domain objects into deterministic JSON-compatible values."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value):
        return {key: to_primitive(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): to_primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_primitive(item) for item in value]
    return value
