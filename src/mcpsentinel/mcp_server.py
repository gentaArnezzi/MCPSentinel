"""MCP-native, operator-constrained wrapper around the MCPSentinel scan pipeline."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from mcp import types
from mcp.server import MCPServer

from . import __version__
from .models import TargetConfig
from .safety import safe_report_payload
from .service import scan

_TRUE_VALUES = {"1", "true", "yes"}

mcp = MCPServer(
    "MCPSentinel",
    title="MCPSentinel MCP security scanner",
    description="Precision-first read-only metadata scans for allowlisted MCP targets.",
    instructions=(
        "Scan only operator-allowlisted HTTP targets. Stdio targets, dynamic execution, "
        "and baseline approval are intentionally unavailable through this server."
    ),
    version=__version__,
)


@mcp.tool(
    name="scan_mcp_server",
    title="Scan an MCP server for security risks",
    description=(
        "Enumerate metadata from an operator-allowlisted HTTP MCP server and return static, "
        "semantic, and baseline security findings. Dynamic tool invocation is "
        "never performed and baselines are never approved from this MCP-native interface."
    ),
    annotations=types.ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
    structured_output=True,
)
async def scan_mcp_server(
    target: str,
    transport: str = "auto",
) -> dict[str, object]:
    """Scan a server after operator-controlled target and egress authorization checks."""
    target_config = _target_from_mcp_request(target, transport)
    report = await scan(
        target_config,
        rules_path=_configured_path("MCPSENTINEL_RULES_PATH"),
        policy_path=_configured_path("MCPSENTINEL_POLICY_PATH"),
        baseline_root=Path(os.environ.get("MCPSENTINEL_MCP_BASELINE_DIR", "~/.mcpsentinel")),
        update_baseline=False,
        judge_kind=os.environ.get("MCPSENTINEL_MCP_JUDGE", "heuristic"),
        judge_model=os.environ.get("MCPSENTINEL_MCP_JUDGE_MODEL", "gpt-4o-mini"),
        semantic_threshold=0.70,
    )
    return safe_report_payload(report)


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

    raise ValueError(
        "MCP-native scanning supports allowlisted HTTP targets only. "
        "Use the human CLI for a trusted stdio target."
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
