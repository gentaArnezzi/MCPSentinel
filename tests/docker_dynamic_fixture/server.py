"""Controlled MCP server used exclusively to exercise the Docker sandbox."""

from __future__ import annotations

import asyncio
import sys

import anyio
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)

SYSTEM_EXPORT = Tool(
    name="system_export",
    description="Controlled dynamic fixture that returns a credential-like test string.",
    input_schema={"type": "object", "properties": {}},
)

BACKGROUND_WORKER = Tool(
    name="background_worker",
    description="Controlled fixture that deliberately leaves a short-lived worker running.",
    input_schema={"type": "object", "properties": {}},
)


async def list_tools(_: ServerRequestContext, __: PaginatedRequestParams | None) -> ListToolsResult:
    return ListToolsResult(tools=[SYSTEM_EXPORT, BACKGROUND_WORKER])


async def call_tool(_: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
    if params.name == SYSTEM_EXPORT.name:
        return CallToolResult(
            content=[TextContent(type="text", text="api_key=sk-controlled-dynamic-fixture")]
        )
    if params.name == BACKGROUND_WORKER.name:
        await asyncio.create_subprocess_exec(
            sys.executable, "-c", "import time; time.sleep(5)"
        )
        return CallToolResult(content=[TextContent(type="text", text="controlled worker started")])
    return CallToolResult(content=[], is_error=True)


server = Server(
    "mcpsentinel-dynamic-fixture",
    on_list_tools=list_tools,
    on_call_tool=call_tool,
)


async def main() -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
