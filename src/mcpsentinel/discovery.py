"""Read-only discovery of MCP server definitions over supported transports."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp import types as mcp_types
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from .models import DescriptorKind, TargetConfig, ToolDescriptor


class DiscoveryError(RuntimeError):
    """Raised when MCPSentinel cannot safely enumerate MCP metadata."""


def _as_dict(value: Any) -> dict[str, Any]:
    """Normalize MCP SDK Pydantic models across compatible SDK versions."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, dict):
        return value
    return {key: item for key, item in vars(value).items() if not key.startswith("_")}


def _descriptor(kind: DescriptorKind, item: Any) -> ToolDescriptor:
    value = _as_dict(item)
    name = str(value.pop("name", None) or value.get("uri", "unnamed"))
    description = str(value.pop("description", "") or "")

    if kind is DescriptorKind.TOOL:
        schema = value.pop("inputSchema", value.pop("input_schema", {})) or {}
    elif kind is DescriptorKind.PROMPT:
        schema = {"arguments": value.pop("arguments", [])}
    else:
        schema = {
            key: value.pop(key) for key in list(value) if key in {"uri", "uriTemplate", "mimeType"}
        }

    return ToolDescriptor(
        kind=kind, name=name, description=description, schema=schema, metadata=value
    )


@asynccontextmanager
async def _session_for(target: TargetConfig) -> AsyncIterator[ClientSession]:
    if target.transport == "http":
        if not target.url:
            raise DiscoveryError("HTTP targets require a URL.")
        async with streamable_http_client(target.url) as (read, write):
            async with ClientSession(read, write) as session:
                yield session
        return

    if target.transport != "stdio" or not target.command:
        raise DiscoveryError(f"Unsupported target transport: {target.transport!r}")

    # Preserve PATH and other process requirements while allowing explicit overrides.
    environment = dict(os.environ)
    environment.update(target.environment)
    parameters = StdioServerParameters(
        command=target.command,
        args=list(target.arguments),
        env=environment,
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            yield session


async def _all_pages(session_method: Any, item_field: str) -> list[Any]:
    """Collect a protocol-paginated descriptor list without making tool calls."""
    cursor: str | None = None
    items: list[Any] = []
    while True:
        params = mcp_types.PaginatedRequestParams(cursor=cursor) if cursor else None
        response = await session_method(params=params)
        items.extend(getattr(response, item_field, []))
        cursor = getattr(response, "nextCursor", None) or getattr(response, "next_cursor", None)
        if cursor is None:
            return items


async def discover(target: TargetConfig) -> tuple[list[ToolDescriptor], dict[str, Any]]:
    """Initialize a session and enumerate metadata without calling any MCP tool."""
    try:
        async with _session_for(target) as session:
            initialized = await session.initialize()
            initialized_data = _as_dict(initialized)
            capabilities = initialized_data.get("capabilities", {}) or {}
            descriptors: list[ToolDescriptor] = []

            if capabilities.get("tools") is not None:
                tools = await _all_pages(session.list_tools, "tools")
                descriptors.extend(_descriptor(DescriptorKind.TOOL, tool) for tool in tools)
            if capabilities.get("prompts") is not None:
                prompts = await _all_pages(session.list_prompts, "prompts")
                descriptors.extend(_descriptor(DescriptorKind.PROMPT, prompt) for prompt in prompts)
            if capabilities.get("resources") is not None:
                server_resources = await _all_pages(session.list_resources, "resources")
                descriptors.extend(
                    _descriptor(DescriptorKind.RESOURCE, resource) for resource in server_resources
                )
                # Templates share the resources capability and are optional in older SDK releases.
                if hasattr(session, "list_resource_templates"):
                    templates = await _all_pages(
                        session.list_resource_templates, "resourceTemplates"
                    )
                    descriptors.extend(
                        _descriptor(DescriptorKind.RESOURCE_TEMPLATE, item) for item in templates
                    )

            metadata = {
                "server": initialized_data.get(
                    "serverInfo", initialized_data.get("server_info", {})
                ),
                "protocol_version": initialized_data.get(
                    "protocolVersion", initialized_data.get("protocol_version")
                ),
            }
            return descriptors, metadata
    except DiscoveryError:
        raise
    except Exception as error:
        raise DiscoveryError(f"MCP metadata discovery failed: {error}") from error
