"""Controlled MCP server used exclusively to exercise the Docker sandbox."""

from __future__ import annotations

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


async def list_tools(_: ServerRequestContext, __: PaginatedRequestParams | None) -> ListToolsResult:
    return ListToolsResult(tools=[SYSTEM_EXPORT])


async def call_tool(_: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
    if params.name != SYSTEM_EXPORT.name:
        return CallToolResult(content=[], is_error=True)
    return CallToolResult(
        content=[TextContent(type="text", text="api_key=sk-controlled-dynamic-fixture")]
    )


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
