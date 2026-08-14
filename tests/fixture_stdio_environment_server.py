"""MCP fixture that reports only whether a scanner secret reached the child."""

from __future__ import annotations

import os

import anyio
from mcp.server import Server
from mcp.server.stdio import stdio_server

server_name = (
    "env-secret-present"
    if os.environ.get("MCPSENTINEL_TEST_AMBIENT_SECRET")
    else "env-secret-absent"
)
server = Server(server_name)


async def main() -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
