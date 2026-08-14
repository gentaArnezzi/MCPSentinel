"""MCP-native, operator-constrained wrapper around the MCPSentinel scan pipeline."""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from urllib.parse import urlparse

from mcp import types
from mcp.server import MCPServer

from .models import TargetConfig, to_primitive
from .service import scan

_TRUE_VALUES = {"1", "true", "yes"}

mcp = MCPServer(
    "MCPSentinel",
    title="MCPSentinel MCP security scanner",
    description="Precision-first read-only metadata scans for allowlisted MCP targets.",
    instructions=(
        "Scan targets only when an operator has configured them in MCPSENTINEL_ALLOWED_HOSTS. "
        "Dynamic execution is intentionally unavailable through this server."
    ),
    version="0.1.1",
)


@mcp.tool(
    name="scan_mcp_server",
    title="Scan an MCP server for security risks",
    description=(
        "Enumerate metadata from an allowlisted MCP server and return static, "
        "semantic, and baseline security findings. Dynamic tool invocation is "
        "never performed from this MCP-native interface."
    ),
    annotations=types.ToolAnnotations(
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    ),
    structured_output=True,
)
async def scan_mcp_server(
    target: str,
    transport: str = "auto",
    update_baseline: bool = False,
) -> dict[str, object]:
    """Scan a server after operator-controlled target and egress authorization checks."""
    target_config = _target_from_mcp_request(target, transport)
    report = await scan(
        target_config,
        rules_path=_configured_path("MCPSENTINEL_RULES_PATH"),
        policy_path=_configured_path("MCPSENTINEL_POLICY_PATH"),
        baseline_root=Path(os.environ.get("MCPSENTINEL_MCP_BASELINE_DIR", "~/.mcpsentinel")),
        update_baseline=update_baseline,
        judge_kind=os.environ.get("MCPSENTINEL_MCP_JUDGE", "heuristic"),
        judge_model=os.environ.get("MCPSENTINEL_MCP_JUDGE_MODEL", "gpt-4o-mini"),
        semantic_threshold=0.70,
    )
    return to_primitive(report)


def _target_from_mcp_request(target: str, transport: str) -> TargetConfig:
    if len(target) > 2048:
        raise ValueError("Target must not exceed 2048 characters.")
    if transport not in {"auto", "http", "stdio"}:
        raise ValueError("transport must be auto, http, or stdio.")
    parsed = urlparse(target)
    effective_transport = transport
    if effective_transport == "auto":
        effective_transport = "http" if parsed.scheme in {"http", "https"} else "stdio"
    if effective_transport == "http":
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("HTTP target must be an absolute http:// or https:// URL.")
        allowed_hosts = {
            host.strip().lower()
            for host in os.environ.get("MCPSENTINEL_ALLOWED_HOSTS", "").split(",")
            if host.strip()
        }
        if not _is_authorized_http_target(parsed, allowed_hosts):
            raise ValueError(
                "Target host is not authorized. Set MCPSENTINEL_ALLOWED_HOSTS "
                "to an explicit host or host:port list."
            )
        return TargetConfig(
            transport="http",
            identity=target,
            url=target,
            restrict_to_public_network=(
                os.environ.get("MCPSENTINEL_ALLOW_PRIVATE_HTTP_TARGETS", "").lower()
                not in _TRUE_VALUES
            ),
        )

    if os.environ.get("MCPSENTINEL_ALLOW_STDIO_TARGETS", "").lower() not in _TRUE_VALUES:
        raise ValueError(
            "Stdio targets are disabled; set MCPSENTINEL_ALLOW_STDIO_TARGETS=true to enable."
        )
    pieces = shlex.split(target)
    if not pieces:
        raise ValueError("A stdio target must contain an executable command.")
    command, *arguments = pieces
    return TargetConfig(
        transport="stdio",
        identity=" ".join(pieces),
        command=command,
        arguments=tuple(arguments),
    )


def _configured_path(variable: str) -> Path | None:
    raw = os.environ.get(variable)
    return Path(raw).expanduser() if raw else None


def _is_authorized_http_target(parsed, allowed_hosts: set[str]) -> bool:
    """Match exact hosts, with an optional exact port in the operator allowlist."""
    host = parsed.hostname.lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host in allowed_hosts or f"{host}:{port}" in allowed_hosts


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
