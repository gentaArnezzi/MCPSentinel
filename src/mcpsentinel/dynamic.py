"""Opt-in Docker sandbox validation for explicitly selected MCP tool calls."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .discovery import _client_for
from .models import (
    Category,
    DescriptorKind,
    DynamicObservation,
    DynamicStatus,
    Finding,
    Severity,
    TargetConfig,
)


class DynamicValidationError(RuntimeError):
    """The opt-in dynamic validation configuration cannot be run safely."""


@dataclass(frozen=True)
class DynamicInvocation:
    tool_name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class DynamicConfig:
    """Sandbox controls deliberately require explicit operator input and ownership."""

    image: str
    invocations: tuple[DynamicInvocation, ...]
    entrypoint: tuple[str, ...] = ()
    timeout_seconds: int = 10
    confidence_threshold: float = 0.80


@dataclass(frozen=True)
class DynamicValidationResult:
    observations: list[DynamicObservation]
    findings: list[Finding]


@dataclass(frozen=True)
class _SandboxTelemetry:
    """Counts from Docker only; never retain process arguments or file paths."""

    process_count: int | None
    filesystem_change_count: int | None
    filesystem_telemetry_truncated: bool = False


@dataclass(frozen=True)
class _DockerOutput:
    lines: list[str]
    truncated: bool = False


_TELEMETRY_TIMEOUT_SECONDS = 2.0


def sandbox_target(config: DynamicConfig, *, cidfile: Path | None = None) -> TargetConfig:
    """Build an unprivileged, network-isolated Docker stdio target without host mounts."""
    if not config.image.strip():
        raise DynamicValidationError("Dynamic validation needs a non-empty Docker image.")
    if shutil.which("docker") is None:
        raise DynamicValidationError("Dynamic validation requires the Docker CLI on PATH.")
    arguments = [
        "run",
        "--rm",
        "--interactive",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--pids-limit=64",
        "--memory=256m",
        "--cpus=0.50",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
        "--workdir=/tmp",
    ]
    if cidfile is not None:
        arguments.extend(("--cidfile", str(cidfile)))
    if config.entrypoint:
        arguments.extend(("--entrypoint", config.entrypoint[0]))
    arguments.append(config.image)
    if config.entrypoint:
        arguments.extend(config.entrypoint[1:])
    return TargetConfig(
        transport="stdio",
        identity=f"docker-sandbox:{config.image}",
        command="docker",
        arguments=tuple(arguments),
    )


async def run_dynamic_validation(
    config: DynamicConfig,
    eligible_findings: list[Finding],
) -> DynamicValidationResult:
    """Invoke selected high-confidence tools in a fresh sandboxed MCP server process.

    The caller must have already required an ownership assertion. No discovery target
    environment, volumes, network, credentials, or process privileges are forwarded.
    """
    eligible_names = {
        finding.subject_name
        for finding in eligible_findings
        if finding.subject_kind is DescriptorKind.TOOL
        and "semantic" in finding.layers
        and finding.confidence >= config.confidence_threshold
    }
    selected_names = {invocation.tool_name for invocation in config.invocations}
    if not selected_names:
        raise DynamicValidationError(
            "Dynamic validation needs at least one --dynamic-invoke value."
        )
    unqualified = sorted(selected_names - eligible_names)
    if unqualified:
        raise DynamicValidationError(
            "Dynamic invocations must name semantic high-confidence findings: "
            + ", ".join(unqualified)
        )

    observations: list[DynamicObservation] = []
    findings: list[Finding] = []
    try:
        for invocation in config.invocations:
            # Never let an earlier selected tool alter in-memory state or /tmp
            # for a later tool. Each invocation starts and removes its own
            # constrained Docker process.
            with tempfile.TemporaryDirectory(prefix="mcpsentinel-dynamic-") as temporary_dir:
                cidfile = Path(temporary_dir) / "container-id"
                target = sandbox_target(config, cidfile=cidfile)
                async with _client_for(target) as session:
                    container_id = await _wait_for_container_id(cidfile)
                    telemetry_before = await _capture_telemetry(container_id)
                    observation, response_finding = await _invoke(
                        session, invocation, config.timeout_seconds
                    )
                    telemetry_after = await _capture_telemetry(container_id)
                observation = replace(
                    observation,
                    process_count_before=telemetry_before.process_count,
                    process_count_after=telemetry_after.process_count,
                    filesystem_change_count=telemetry_after.filesystem_change_count,
                    filesystem_change_count_before=telemetry_before.filesystem_change_count,
                    filesystem_change_delta=_filesystem_delta(telemetry_before, telemetry_after),
                    filesystem_telemetry_truncated=(
                        telemetry_before.filesystem_telemetry_truncated
                        or telemetry_after.filesystem_telemetry_truncated
                    ),
                )
                observations.append(observation)
                if response_finding is not None:
                    findings.append(response_finding)
                residual_process_finding = _residual_process_finding(
                    invocation, telemetry_before, telemetry_after
                )
                if residual_process_finding is not None:
                    findings.append(residual_process_finding)
    except DynamicValidationError:
        raise
    except Exception as error:
        raise DynamicValidationError(f"Docker sandbox validation failed: {error}") from error
    return DynamicValidationResult(observations=observations, findings=findings)


async def _wait_for_container_id(cidfile: Path) -> str | None:
    """Wait briefly for Docker to write the per-invocation container ID."""
    for _ in range(20):
        try:
            container_id = cidfile.read_text(encoding="utf-8").strip()
        except OSError:
            container_id = ""
        is_container_id = len(container_id) == 64 and all(
            character in "0123456789abcdef" for character in container_id
        )
        if is_container_id:
            return container_id
        await asyncio.sleep(0.05)
    return None


async def _capture_telemetry(container_id: str | None) -> _SandboxTelemetry:
    """Read bounded Docker counters while the container is still alive."""
    if container_id is None:
        return _SandboxTelemetry(process_count=None, filesystem_change_count=None)
    processes, filesystem_changes = await asyncio.gather(
        _docker_output("top", container_id, "-eo", "pid"),
        _docker_output("diff", container_id),
    )
    return _SandboxTelemetry(
        process_count=_process_count(processes.lines if processes is not None else None),
        filesystem_change_count=(
            len(filesystem_changes.lines) if filesystem_changes is not None else None
        ),
        filesystem_telemetry_truncated=(
            filesystem_changes.truncated if filesystem_changes is not None else False
        ),
    )


async def _docker_output(*arguments: str) -> _DockerOutput | None:
    """Return bounded Docker CLI output without retaining untrusted telemetry details."""
    try:
        process = await asyncio.create_subprocess_exec(
            "docker",
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError:
        return None
    try:
        stdout, _ = await asyncio.wait_for(
            process.communicate(), timeout=_TELEMETRY_TIMEOUT_SECONDS
        )
    except TimeoutError:
        process.kill()
        await process.communicate()
        return None
    if process.returncode != 0:
        return None
    return _DockerOutput(
        lines=stdout[:65536].decode("utf-8", errors="replace").splitlines(),
        truncated=len(stdout) > 65536,
    )


def _filesystem_delta(before: _SandboxTelemetry, after: _SandboxTelemetry) -> int | None:
    if before.filesystem_change_count is None or after.filesystem_change_count is None:
        return None
    return after.filesystem_change_count - before.filesystem_change_count


def _process_count(lines: list[str] | None) -> int | None:
    """Count `docker top` rows while discarding its header and command data."""
    if not lines:
        return None
    return max(0, len([line for line in lines[1:] if line.strip()]))


def _residual_process_finding(
    invocation: DynamicInvocation,
    before: _SandboxTelemetry,
    after: _SandboxTelemetry,
) -> Finding | None:
    if (
        before.process_count is None
        or after.process_count is None
        or after.process_count <= before.process_count
    ):
        return None
    return Finding(
        rule_id="MCP-D002",
        title="Dynamic invocation left additional process(es) running",
        category=Category.COMMAND_EXECUTION,
        severity=Severity.MEDIUM,
        message=(
            "The sandbox had more processes after the tool returned than before the call."
        ),
        subject_kind=DescriptorKind.TOOL,
        subject_name=invocation.tool_name,
        evidence=(
            "Sandbox process count increased from "
            f"{before.process_count} to {after.process_count}; process details were not retained.",
        ),
        confidence=0.80,
        layers=("dynamic",),
        rationale=(
            "Review whether the owned tool intentionally leaves background work running. "
            "The process remains constrained to the disposable, network-isolated container."
        ),
    )


async def _invoke(
    session: Any,
    invocation: DynamicInvocation,
    timeout_seconds: int,
) -> tuple[DynamicObservation, Finding | None]:
    started = time.monotonic()
    try:
        result = await asyncio.wait_for(
            session.call_tool(invocation.tool_name, invocation.arguments),
            timeout=timeout_seconds,
        )
    except TimeoutError:
        return (
            DynamicObservation(
                tool_name=invocation.tool_name,
                status=DynamicStatus.TIMEOUT,
                duration_ms=round((time.monotonic() - started) * 1000),
                detail=f"Tool call exceeded the {timeout_seconds}s sandbox timeout.",
            ),
            None,
        )
    except Exception as error:
        return (
            DynamicObservation(
                tool_name=invocation.tool_name,
                status=DynamicStatus.ERROR,
                duration_ms=round((time.monotonic() - started) * 1000),
                detail=f"MCP call failed: {type(error).__name__}",
            ),
            None,
        )

    payload = _as_json(result)
    status = (
        DynamicStatus.ERROR
        if payload.get("isError", payload.get("is_error", False))
        else DynamicStatus.SUCCESS
    )
    response_digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    content = payload.get("content", [])
    content_types = tuple(
        sorted({str(item.get("type", "unknown")) for item in content if isinstance(item, dict)})
    )
    observation = DynamicObservation(
        tool_name=invocation.tool_name,
        status=status,
        duration_ms=round((time.monotonic() - started) * 1000),
        response_digest=response_digest,
        content_types=content_types,
    )
    if _contains_secret_material(content):
        return observation, Finding(
            rule_id="MCP-D001",
            title="Dynamic invocation returned credential-like material",
            category=Category.SECRET_EXFILTRATION,
            severity=Severity.CRITICAL,
            message=(
                "A sandboxed tool invocation returned text that resembles a "
                "credential or private key."
            ),
            subject_kind=DescriptorKind.TOOL,
            subject_name=invocation.tool_name,
            evidence=(
                "Dynamic response matched the credential exposure detector; "
                "content is not retained.",
            ),
            confidence=0.90,
            layers=("dynamic",),
            rationale=(
                "Review the tool response and authorization boundary using a "
                "controlled test fixture."
            ),
        )
    return observation, None


def _as_json(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, dict):
        return value
    return {key: item for key, item in vars(value).items() if not key.startswith("_")}


def _contains_secret_material(content: Any) -> bool:
    serialized = json.dumps(content, sort_keys=True).lower()
    patterns = (
        "-----begin private key-----",
        "sk-",
        "api_key",
        "api key",
        "authorization: bearer",
        "aws_secret_access_key",
    )
    return any(pattern in serialized for pattern in patterns)
