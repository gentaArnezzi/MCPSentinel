from __future__ import annotations

import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcpsentinel import mcp_server


async def test_mcp_native_server_rejects_unallowlisted_http_targets(monkeypatch) -> None:
    monkeypatch.delenv("MCPSENTINEL_ALLOWED_HOSTS", raising=False)

    with pytest.raises(ValueError, match="not authorized"):
        await mcp_server.scan_mcp_server("https://untrusted.example/mcp")


def test_mcp_native_http_allowlist_supports_explicit_ports(monkeypatch) -> None:
    monkeypatch.setenv("MCPSENTINEL_ALLOWED_HOSTS", "scanner.example:8443")
    monkeypatch.delenv("MCPSENTINEL_ALLOW_PRIVATE_HTTP_TARGETS", raising=False)

    target = mcp_server._target_from_mcp_request(
        "https://scanner.example:8443/mcp", transport="http"
    )

    assert target.restrict_to_public_network is True
    with pytest.raises(ValueError, match="not authorized"):
        mcp_server._target_from_mcp_request("https://scanner.example/mcp", transport="http")


def test_mcp_native_can_explicitly_allow_a_trusted_private_network(monkeypatch) -> None:
    monkeypatch.setenv("MCPSENTINEL_ALLOWED_HOSTS", "localhost")
    monkeypatch.setenv("MCPSENTINEL_ALLOW_PRIVATE_HTTP_TARGETS", "true")

    target = mcp_server._target_from_mcp_request("http://localhost:8765/mcp", transport="http")

    assert target.restrict_to_public_network is False


async def test_mcp_native_stdio_server_exposes_the_scan_tool() -> None:
    parameters = StdioServerParameters(
        command=sys.executable, args=["-m", "mcpsentinel.mcp_server"]
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()

    assert [tool.name for tool in tools.tools] == ["scan_mcp_server"]
