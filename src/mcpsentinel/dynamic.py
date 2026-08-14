"""Opt-in Docker sandbox validation for explicitly selected MCP tool calls."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import time
from dataclasses import dataclass
from typing import Any

from .discovery import _session_for
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


def sandbox_target(config: DynamicConfig) -> TargetConfig:
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
    target = sandbox_target(config)
    try:
        async with _session_for(target) as session:
            await session.initialize()
            for invocation in config.invocations:
                observation, finding = await _invoke(session, invocation, config.timeout_seconds)
                observations.append(observation)
                if finding is not None:
                    findings.append(finding)
    except DynamicValidationError:
        raise
    except Exception as error:
        raise DynamicValidationError(f"Docker sandbox validation failed: {error}") from error
    return DynamicValidationResult(observations=observations, findings=findings)


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
