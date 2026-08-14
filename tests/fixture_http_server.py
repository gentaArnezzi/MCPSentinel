"""Controlled Streamable HTTP MCP server used only by integration tests."""

from __future__ import annotations

import os

from mcp.server import MCPServer

mcp = MCPServer("mcpsentinel-http-test-server")


@mcp.tool()
def local_lookup(query: str) -> str:
    """Return a controlled fixture response without performing an external request."""
    return query


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=int(os.environ["MCPSENTINEL_HTTP_FIXTURE_PORT"]),
    )
