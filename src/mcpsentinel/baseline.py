"""Local baseline snapshots and semantic-result cache."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import (
    Category,
    DescriptorKind,
    Finding,
    JudgeVerdict,
    Severity,
    TargetConfig,
    ToolDescriptor,
    to_primitive,
)
from .safety import safe_target_identity


def stable_hash(value: Any) -> str:
    encoded = json.dumps(to_primitive(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class BaselineComparison:
    findings: list[Finding]
    prior_exists: bool


class BaselineStore:
    """Stores only server metadata snapshots, not invocation data or credentials."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser()
        self.snapshot_dir = self.root / "baselines"
        self.cache_dir = self.root / "judge-cache"

    def _target_key(self, target: TargetConfig) -> str:
        return stable_hash({"transport": target.transport, "identity": target.identity})

    def _snapshot_path(self, target: TargetConfig) -> Path:
        return self.snapshot_dir / f"{self._target_key(target)}.json"

    def load_snapshot(self, target: TargetConfig) -> dict[str, Any] | None:
        path = self._snapshot_path(target)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(f"Could not read baseline snapshot {path}: {error}") from error

    def compare(
        self, target: TargetConfig, descriptors: list[ToolDescriptor]
    ) -> BaselineComparison:
        previous = self.load_snapshot(target)
        if previous is None:
            return BaselineComparison(findings=[], prior_exists=False)

        current = {item.key: stable_hash(item) for item in descriptors}
        current_field_hashes = {item.key: _field_hashes(item) for item in descriptors}
        old = previous.get("descriptor_hashes", {})
        old_field_hashes = previous.get("descriptor_field_hashes", {})
        findings: list[Finding] = []

        for key in sorted(current.keys() - old.keys()):
            kind, name = key.split(":", maxsplit=1)
            findings.append(_baseline_finding(kind, name, "added", Severity.MEDIUM))
        for key in sorted(old.keys() - current.keys()):
            kind, name = key.split(":", maxsplit=1)
            findings.append(_baseline_finding(kind, name, "removed", Severity.HIGH))
        for key in sorted(current.keys() & old.keys()):
            if current[key] != old[key]:
                kind, name = key.split(":", maxsplit=1)
                changed_fields = tuple(
                    field
                    for field in ("description", "schema", "metadata")
                    if current_field_hashes[key].get(field)
                    != old_field_hashes.get(key, {}).get(field)
                )
                findings.append(
                    _baseline_finding(
                        kind,
                        name,
                        "changed",
                        Severity.HIGH,
                        changed_fields=changed_fields,
                    )
                )
        return BaselineComparison(findings=findings, prior_exists=True)

    def save_snapshot(self, target: TargetConfig, descriptors: list[ToolDescriptor]) -> None:
        descriptor_hashes = {item.key: stable_hash(item) for item in descriptors}
        descriptor_field_hashes = {item.key: _field_hashes(item) for item in descriptors}
        payload = {
            "version": 2,
            "target": {"transport": target.transport, "identity": safe_target_identity(target)},
            "captured_at": datetime.now(UTC).isoformat(),
            "descriptor_hashes": descriptor_hashes,
            "descriptor_field_hashes": descriptor_field_hashes,
        }
        self._atomic_write(self._snapshot_path(target), payload)

    def load_judgement(self, key: str) -> JudgeVerdict | None:
        path = self.cache_dir / f"{key}.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError):
            return None
        try:
            return JudgeVerdict(
                label=payload["label"],
                confidence=float(payload["confidence"]),
                rationale=payload["rationale"],
                judge=payload["judge"],
                cache_hit=True,
            )
        except (KeyError, TypeError, ValueError):
            return None

    def save_judgement(self, key: str, verdict: JudgeVerdict) -> None:
        self._atomic_write(self.cache_dir / f"{key}.json", to_primitive(verdict))

    @staticmethod
    def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)


def _field_hashes(descriptor: ToolDescriptor) -> dict[str, str]:
    return {
        "description": stable_hash(descriptor.description),
        "schema": stable_hash(descriptor.schema),
        "metadata": stable_hash(descriptor.metadata),
    }


def _baseline_finding(
    kind: str,
    name: str,
    change: str,
    severity: Severity,
    *,
    changed_fields: tuple[str, ...] = (),
) -> Finding:
    try:
        descriptor_kind = DescriptorKind(kind)
    except ValueError:
        descriptor_kind = DescriptorKind.TOOL
    field_summary = ", ".join(changed_fields)
    evidence = (
        f"Baseline diff: changed fields: {field_summary}."
        if changed_fields
        else f"Baseline diff: descriptor was {change}.",
    )
    message = f"The {descriptor_kind.value} '{name}' was {change} since the previous scan."
    if field_summary:
        message += f" Changed fields: {field_summary}."
    return Finding(
        rule_id="MCP-B001",
        title="MCP definition changed since trusted baseline",
        category=Category.RUG_PULL,
        severity=severity,
        message=message,
        subject_kind=descriptor_kind,
        subject_name=name,
        evidence=evidence,
        confidence=0.92,
        layers=("baseline",),
        rationale=(
            "A metadata change can be legitimate, but it requires review "
            "before the server remains trusted."
        ),
    )
