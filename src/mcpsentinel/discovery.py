"""Read-only discovery of MCP server definitions over supported transports."""

from __future__ import annotations

import asyncio
import ipaddress
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx2
from mcp import ClientSession, StdioServerParameters
from mcp import types as mcp_types
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from .models import DescriptorKind, TargetConfig, ToolDescriptor

DISCOVERY_TIMEOUT_SECONDS = 30.0
HTTP_CONNECT_TIMEOUT_SECONDS = 5.0
HTTP_READ_TIMEOUT_SECONDS = 20.0
HTTP_WRITE_TIMEOUT_SECONDS = 10.0
HTTP_POOL_TIMEOUT_SECONDS = 5.0
DNS_LOOKUP_TIMEOUT_SECONDS = 5.0
MAX_DESCRIPTOR_PAGES = 100
MAX_DESCRIPTORS_PER_CAPABILITY = 1_000


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
        if target.restrict_to_public_network:
            await _require_public_http_destination(target.url)
        async with _http_client() as http_client:
            async with streamable_http_client(target.url, http_client=http_client) as (read, write):
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


def _http_client() -> httpx2.AsyncClient:
    """Create an egress-constrained client for metadata discovery.

    Scanner targets are untrusted: redirects could bypass an operator's host
    allowlist and ambient proxy settings could unexpectedly receive metadata.
    The SDK accepts a caller-owned client, so these controls apply to every
    HTTP request in the MCP session.
    """
    return httpx2.AsyncClient(
        follow_redirects=False,
        trust_env=False,
        timeout=httpx2.Timeout(
            HTTP_READ_TIMEOUT_SECONDS,
            connect=HTTP_CONNECT_TIMEOUT_SECONDS,
            read=HTTP_READ_TIMEOUT_SECONDS,
            write=HTTP_WRITE_TIMEOUT_SECONDS,
            pool=HTTP_POOL_TIMEOUT_SECONDS,
        ),
    )


async def _require_public_http_destination(url: str) -> None:
    """Reject a hostname that resolves to a private or reserved address.

    This is used only by the MCP-native wrapper after its operator allowlist
    check. The CLI keeps its local-development behavior, while the wrapper
    avoids becoming an SSRF pivot for callers that can choose a target URL.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if not parsed.hostname:
        raise DiscoveryError("HTTP targets require a hostname.")
    try:
        records = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                parsed.hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
            ),
            timeout=DNS_LOOKUP_TIMEOUT_SECONDS,
        )
    except TimeoutError as error:
        raise DiscoveryError("HTTP target DNS lookup timed out.") from error
    except OSError as error:
        raise DiscoveryError(f"HTTP target hostname could not be resolved: {error}") from error

    addresses = {record[4][0] for record in records}
    if not addresses:
        raise DiscoveryError("HTTP target hostname resolved to no addresses.")
    non_public = []
    for address in addresses:
        try:
            if not ipaddress.ip_address(address).is_global:
                non_public.append(address)
        except ValueError as error:
            raise DiscoveryError(
                f"HTTP target returned an invalid IP address: {address}"
            ) from error
    if non_public:
        raise DiscoveryError(
            "HTTP target resolved to a private or reserved address; set "
            "MCPSENTINEL_ALLOW_PRIVATE_HTTP_TARGETS=true only for a trusted local network."
        )


async def _all_pages(session_method: Any, item_field: str) -> list[Any]:
    """Collect a protocol-paginated descriptor list without making tool calls."""
    cursor: str | None = None
    items: list[Any] = []
    for _ in range(MAX_DESCRIPTOR_PAGES):
        params = mcp_types.PaginatedRequestParams(cursor=cursor) if cursor else None
        response = await session_method(params=params)
        items.extend(getattr(response, item_field, []))
        if len(items) > MAX_DESCRIPTORS_PER_CAPABILITY:
            raise DiscoveryError(
                "MCP server returned more than "
                f"{MAX_DESCRIPTORS_PER_CAPABILITY} {item_field} entries."
            )
        cursor = getattr(response, "nextCursor", None) or getattr(response, "next_cursor", None)
        if cursor is None:
            return items
    raise DiscoveryError(f"MCP server exceeded the {MAX_DESCRIPTOR_PAGES}-page {item_field} limit.")


async def discover(target: TargetConfig) -> tuple[list[ToolDescriptor], dict[str, Any]]:
    """Initialize a session and enumerate metadata without calling any MCP tool."""
    try:
        async with asyncio.timeout(DISCOVERY_TIMEOUT_SECONDS):
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
                    descriptors.extend(
                        _descriptor(DescriptorKind.PROMPT, prompt) for prompt in prompts
                    )
                if capabilities.get("resources") is not None:
                    server_resources = await _all_pages(session.list_resources, "resources")
                    descriptors.extend(
                        _descriptor(DescriptorKind.RESOURCE, resource)
                        for resource in server_resources
                    )
                    # Templates share the resources capability and are optional
                    # in older SDK releases.
                    if hasattr(session, "list_resource_templates"):
                        templates = await _all_pages(
                            session.list_resource_templates, "resourceTemplates"
                        )
                        descriptors.extend(
                            _descriptor(DescriptorKind.RESOURCE_TEMPLATE, item)
                            for item in templates
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
    except TimeoutError as error:
        raise DiscoveryError(
            f"MCP metadata discovery exceeded the {DISCOVERY_TIMEOUT_SECONDS:g}s deadline."
        ) from error
    except DiscoveryError:
        raise
    except Exception as error:
        raise DiscoveryError(f"MCP metadata discovery failed: {error}") from error
