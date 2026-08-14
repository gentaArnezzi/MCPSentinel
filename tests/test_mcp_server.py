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


async def test_mcp_native_stdio_server_exposes_the_scan_tool() -> None:
    parameters = StdioServerParameters(
        command=sys.executable, args=["-m", "mcpsentinel.mcp_server"]
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()

    assert [tool.name for tool in tools.tools] == ["scan_mcp_server"]
