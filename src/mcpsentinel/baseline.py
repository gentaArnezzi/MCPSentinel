"""Local baseline snapshots and semantic-result cache."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
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
from .safety import has_sensitive_auth_context, safe_target_identity, sanitize_text


def stable_hash(value: Any) -> str:
    encoded = json.dumps(to_primitive(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def stable_server_identity(discovery_metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Extract only stable, bounded protocol identity fields from discovery metadata."""
    metadata = discovery_metadata or {}
    server = metadata.get("server") if isinstance(metadata.get("server"), dict) else {}
    capabilities = metadata.get("capabilities", [])
    if not isinstance(capabilities, (list, tuple, set)):
        capabilities = []

    def stable_text(value: Any) -> str:
        raw = str(value or "")
        safe = sanitize_text(raw)
        if safe != raw or len(safe) > 512:
            return safe[:400] + " [sha256:" + stable_hash(raw) + "]"
        return safe

    return {
        "name": stable_text(server.get("name")),
        "version": stable_text(server.get("version")),
        "protocol_version": stable_text(metadata.get("protocol_version")),
        "capabilities": sorted(
            {stable_text(value) for value in capabilities if stable_text(value)}
        ),
    }


def duplicate_descriptor_keys(descriptors: list[ToolDescriptor]) -> tuple[str, ...]:
    counts: dict[str, int] = {}
    for descriptor in descriptors:
        counts[descriptor.key] = counts.get(descriptor.key, 0) + 1
    return tuple(sorted(key for key, count in counts.items() if count > 1))


def definition_fingerprint(
    target: TargetConfig,
    descriptors: list[ToolDescriptor],
    discovery_metadata: dict[str, Any] | None = None,
) -> str:
    """Return a stable identity for exactly the MCP definition that was reviewed.

    The endpoint identity is credential-safe and descriptors are ordered by their
    public key, so a server returning the same definition in a different order
    does not invalidate a human review.
    """
    return stable_hash(
        {
            "format": "mcpsentinel-definition-v2",
            "target": {
                "transport": target.transport,
                "identity": safe_target_identity(target),
            },
            "descriptors": [
                {"key": descriptor.key, "sha256": stable_hash(descriptor)}
                for descriptor in sorted(descriptors, key=lambda item: item.key)
            ],
            "server_identity": stable_server_identity(discovery_metadata),
        }
    )


@dataclass(frozen=True)
class BaselineComparison:
    findings: list[Finding]
    prior_exists: bool
    reapproval_required: bool = False
    notice: str | None = None


@dataclass(frozen=True)
class _LoadedSnapshot:
    payload: dict[str, Any] | None
    source: str


class BaselineStore:
    """Stores only server metadata snapshots, not invocation data or credentials."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser()
        self.snapshot_dir = self.root / "baselines"
        self.cache_dir = self.root / "judge-cache"
        self.scope_key_path = self.root / ".baseline-scope-key"

    def _target_key(self, target: TargetConfig) -> str:
        """Key snapshots by opaque local auth scope, never a display identity."""
        material = json.dumps(
            {
                "transport": target.transport,
                "identity": target.identity,
                "url": target.url,
                "command": target.command,
                "arguments": target.arguments,
                "environment": target.environment,
                "inherit_environment": target.inherit_environment,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(self._scope_key(), material, hashlib.sha256).hexdigest()

    def _scope_key(self) -> bytes:
        """Get a local-only random HMAC key without retaining raw credentials."""
        try:
            key = self.scope_key_path.read_bytes()
        except FileNotFoundError:
            self.root.mkdir(parents=True, exist_ok=True)
            generated = secrets.token_bytes(32)
            descriptor, temporary_name = tempfile.mkstemp(
                dir=self.root,
                prefix=".baseline-scope-key.",
                suffix=".tmp",
            )
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as key_file:
                    if os.name == "posix":
                        os.fchmod(key_file.fileno(), 0o600)
                    key_file.write(generated)
                    key_file.flush()
                    os.fsync(key_file.fileno())
                try:
                    os.link(temporary, self.scope_key_path)
                except FileExistsError:
                    key = self.scope_key_path.read_bytes()
                else:
                    key = generated
            finally:
                temporary.unlink(missing_ok=True)
        except OSError as error:
            message = f"Could not read baseline scope key {self.scope_key_path}: {error}"
            raise RuntimeError(message) from error
        if len(key) != 32:
            raise RuntimeError(f"Baseline scope key {self.scope_key_path} is invalid.")
        return key

    @staticmethod
    def _v086_target_key(target: TargetConfig) -> str:
        """Locate v0.8.6 credential-safe snapshot names during local migration."""
        return stable_hash(
            {"transport": target.transport, "identity": safe_target_identity(target)}
        )

    @staticmethod
    def _legacy_target_key(target: TargetConfig) -> str:
        """Locate safe pre-v0.8.6 snapshots without rewriting their paths."""
        return stable_hash({"transport": target.transport, "identity": target.identity})

    def _snapshot_path(self, target: TargetConfig) -> Path:
        return self.snapshot_dir / f"{self._target_key(target)}.json"

    def _load_snapshot(self, target: TargetConfig) -> _LoadedSnapshot:
        path = self._snapshot_path(target)
        try:
            return _LoadedSnapshot(json.loads(path.read_text(encoding="utf-8")), "current")
        except FileNotFoundError:
            for source, key in (
                ("v0.8.6", self._v086_target_key(target)),
                ("legacy", self._legacy_target_key(target)),
            ):
                legacy_path = self.snapshot_dir / f"{key}.json"
                if legacy_path == path:
                    continue
                try:
                    payload = json.loads(legacy_path.read_text(encoding="utf-8"))
                except FileNotFoundError:
                    continue
                except (OSError, json.JSONDecodeError) as error:
                    message = f"Could not read baseline snapshot {legacy_path}: {error}"
                    raise RuntimeError(message) from error
                if has_sensitive_auth_context(target):
                    return _LoadedSnapshot(None, "blocked-auth-legacy")
                return _LoadedSnapshot(payload, source)
            return _LoadedSnapshot(None, "missing")
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(f"Could not read baseline snapshot {path}: {error}") from error

    def load_snapshot(self, target: TargetConfig) -> dict[str, Any] | None:
        return self._load_snapshot(target).payload

    def compare(
        self,
        target: TargetConfig,
        descriptors: list[ToolDescriptor],
        discovery_metadata: dict[str, Any] | None = None,
    ) -> BaselineComparison:
        loaded = self._load_snapshot(target)
        previous = loaded.payload
        if previous is None:
            if loaded.source == "blocked-auth-legacy":
                return BaselineComparison(
                    findings=[],
                    prior_exists=False,
                    reapproval_required=True,
                    notice=(
                        "A legacy baseline exists, but MCPSentinel cannot safely associate it "
                        "with the current authentication context. Re-scan and approve a new "
                        "baseline."
                    ),
                )
            return BaselineComparison(findings=[], prior_exists=False)

        current = {item.key: stable_hash(item) for item in descriptors}
        current_field_hashes = {item.key: _field_hashes(item) for item in descriptors}
        old = previous.get("descriptor_hashes", {})
        old_field_hashes = previous.get("descriptor_field_hashes", {})
        findings: list[Finding] = []

        version = previous.get("version")
        reapproval_required = version != 5
        notice = None
        if reapproval_required:
            notice = (
                "This baseline predates identity-aware snapshot format v5. Descriptor changes "
                "were compared conservatively, but a fresh approval is required before the "
                "current server identity is trusted."
            )
        elif discovery_metadata is not None:
            old_identity = previous.get("server_identity", {})
            current_identity = stable_server_identity(discovery_metadata)
            if old_identity != current_identity:
                findings.append(_server_identity_finding(old_identity, current_identity))

        if duplicate_descriptor_keys(descriptors):
            return BaselineComparison(
                findings=findings,
                prior_exists=True,
                reapproval_required=True,
                notice="Duplicate descriptor identities prevent an exact baseline comparison.",
            )

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
        return BaselineComparison(
            findings=findings,
            prior_exists=True,
            reapproval_required=reapproval_required,
            notice=notice,
        )

    def save_snapshot(
        self,
        target: TargetConfig,
        descriptors: list[ToolDescriptor],
        discovery_metadata: dict[str, Any] | None = None,
    ) -> None:
        duplicates = duplicate_descriptor_keys(descriptors)
        if duplicates:
            raise ValueError(
                "Cannot save an ambiguous baseline with duplicate descriptor identities: "
                + ", ".join(duplicates)
            )
        descriptor_hashes = {item.key: stable_hash(item) for item in descriptors}
        descriptor_field_hashes = {item.key: _field_hashes(item) for item in descriptors}
        server_identity = stable_server_identity(discovery_metadata)
        payload = {
            "version": 5,
            "target": {"transport": target.transport, "identity": safe_target_identity(target)},
            "captured_at": datetime.now(UTC).isoformat(),
            "definition_fingerprint": definition_fingerprint(
                target, descriptors, discovery_metadata
            ),
            "server_identity": server_identity,
            "server_identity_fingerprint": stable_hash(server_identity),
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
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                if os.name == "posix":
                    os.fchmod(output.fileno(), 0o600)
                json.dump(payload, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            if os.name == "posix":
                os.chmod(path, 0o600)
        finally:
            temporary.unlink(missing_ok=True)


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


def _server_identity_finding(previous: dict[str, Any], current: dict[str, Any]) -> Finding:
    fields = ("name", "version", "protocol_version", "capabilities")
    changes = tuple(
        f"{field}: {previous.get(field, '')!r} -> {current.get(field, '')!r}"
        for field in fields
        if previous.get(field) != current.get(field)
    )
    return Finding(
        rule_id="MCP-B002",
        title="MCP server identity changed since trusted baseline",
        category=Category.PROTOCOL_INTEGRITY,
        severity=Severity.MEDIUM,
        message="The server identity or negotiated protocol changed since baseline approval.",
        subject_kind=DescriptorKind.SERVER_IDENTITY,
        subject_name=str(current.get("name") or previous.get("name") or "server_identity"),
        evidence=changes,
        confidence=0.95,
        layers=("baseline",),
        rationale=(
            "Version and protocol changes can be legitimate, but the stable server identity is "
            "part of the reviewed trust boundary and requires explicit review."
        ),
    )
