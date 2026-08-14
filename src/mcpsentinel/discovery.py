"""Read-only discovery of MCP server definitions over supported transports."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlparse

import httpcore2
import httpx2
from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from .models import DescriptorKind, DescriptorTruncation, TargetConfig, ToolDescriptor

DISCOVERY_TIMEOUT_SECONDS = 30.0
HTTP_CONNECT_TIMEOUT_SECONDS = 5.0
HTTP_READ_TIMEOUT_SECONDS = 20.0
HTTP_WRITE_TIMEOUT_SECONDS = 10.0
HTTP_POOL_TIMEOUT_SECONDS = 5.0
DNS_LOOKUP_TIMEOUT_SECONDS = 5.0
MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_DESCRIPTOR_PAGES = 100
MAX_DESCRIPTORS_PER_CAPABILITY = 1_000
MAX_DESCRIPTOR_NAME_BYTES = 4 * 1024
MAX_DESCRIPTOR_DESCRIPTION_BYTES = 64 * 1024
MAX_DESCRIPTOR_SCHEMA_BYTES = 192 * 1024
MAX_DESCRIPTOR_METADATA_BYTES = 192 * 1024
MAX_DESCRIPTOR_TOTAL_BYTES = 512 * 1024

# The stdio server is an untrusted child process. It gets only an execution
# path and locale by default; credentials and home-directory lookup variables
# stay with the scanner unless the operator explicitly opts in.
_SAFE_STDIO_ENVIRONMENT_KEYS = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
)


class DiscoveryError(RuntimeError):
    """Raised when MCPSentinel cannot safely enumerate MCP metadata."""


class _PinnedPublicNetworkBackend(httpcore2.AsyncNetworkBackend):
    """Connect a validated hostname only to its already-approved addresses.

    httpcore retains the original hostname as the HTTP Host header and TLS SNI
    name. This backend changes only the TCP destination, preventing a second
    DNS lookup from turning an allowlisted public hostname into an internal
    destination after validation.
    """

    def __init__(
        self,
        hostname: str,
        port: int,
        addresses: tuple[str, ...],
        delegate: httpcore2.AsyncNetworkBackend | None = None,
    ) -> None:
        self._hostname = hostname.lower()
        self._port = port
        self._addresses = addresses
        self._delegate = delegate or httpcore2.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: object | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        if (host.lower(), port) != (self._hostname, self._port):
            raise httpcore2.ConnectError("Refused an HTTP connection outside the validated target.")
        last_error: httpcore2.ConnectError | httpcore2.ConnectTimeout | None = None
        for address in self._addresses:
            try:
                return await self._delegate.connect_tcp(
                    host=address,
                    port=port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore2.ConnectError, httpcore2.ConnectTimeout) as error:
                last_error = error
        if last_error is not None:
            raise last_error
        raise httpcore2.ConnectError("Validated HTTP target did not provide a connectable address.")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: object | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        raise httpcore2.ConnectError("Unix-socket connections are not permitted for HTTP targets.")

    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)


class _PinnedAsyncHTTPTransport(httpx2.AsyncHTTPTransport):
    """HTTPX transport backed by a DNS-pinning network backend."""

    def __init__(self, hostname: str, port: int, addresses: tuple[str, ...]) -> None:
        limits = httpx2.Limits()
        self._pool = httpcore2.AsyncConnectionPool(
            ssl_context=httpx2.create_ssl_context(verify=True, trust_env=False),
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=True,
            http2=False,
            retries=0,
            network_backend=_PinnedPublicNetworkBackend(hostname, port, addresses),
        )


class _BoundedAsyncByteStream(httpx2.AsyncByteStream):
    """Abort an HTTP response before the MCP SDK can decode an unbounded body."""

    def __init__(self, stream: httpx2.AsyncByteStream, maximum_bytes: int) -> None:
        self._stream = stream
        self._maximum_bytes = maximum_bytes

    async def __aiter__(self) -> AsyncIterator[bytes]:
        received = 0
        async for chunk in self._stream:
            received += len(chunk)
            if received > self._maximum_bytes:
                await self.aclose()
                raise httpx2.StreamError(
                    f"HTTP response exceeded the {self._maximum_bytes} byte safety limit."
                )
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class _BoundedResponseTransport(httpx2.AsyncBaseTransport):
    """Apply a raw body ceiling to every Streamable HTTP response."""

    def __init__(self, delegate: httpx2.AsyncBaseTransport, maximum_bytes: int) -> None:
        self._delegate = delegate
        self._maximum_bytes = maximum_bytes

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        response = await self._delegate.handle_async_request(request)
        content_length = response.headers.get("content-length")
        content_encoding = response.headers.get("content-encoding", "identity").lower()
        try:
            declared_bytes = int(content_length) if content_length is not None else None
        except ValueError:
            declared_bytes = None
        if content_encoding not in {"", "identity"}:
            await response.aclose()
            raise httpx2.StreamError("HTTP responses with content encoding are not permitted.")
        if declared_bytes is not None and declared_bytes > self._maximum_bytes:
            await response.aclose()
            raise httpx2.StreamError(
                f"HTTP response exceeded the {self._maximum_bytes} byte safety limit."
            )
        assert isinstance(response.stream, httpx2.AsyncByteStream)
        response.stream = _BoundedAsyncByteStream(response.stream, self._maximum_bytes)
        return response

    async def aclose(self) -> None:
        await self._delegate.aclose()


def _as_dict(value: Any) -> dict[str, Any]:
    """Normalize MCP SDK Pydantic models across compatible SDK versions."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, dict):
        return value
    return {key: item for key, item in vars(value).items() if not key.startswith("_")}


def _descriptor(kind: DescriptorKind, item: Any) -> ToolDescriptor:
    value = _as_dict(item)
    name = str(
        value.pop("name", None)
        or value.get("uri")
        or value.get("uriTemplate")
        or value.get("uri_template")
        or "unnamed"
    )
    description = str(value.pop("description", "") or "")

    if kind is DescriptorKind.TOOL:
        schema = value.pop("inputSchema", value.pop("input_schema", {})) or {}
    elif kind is DescriptorKind.PROMPT:
        schema = {"arguments": value.pop("arguments", [])}
    else:
        schema = _resource_schema(value)

    return _bounded_descriptor(kind, name, description, schema, value)


def _resource_schema(value: dict[str, Any]) -> dict[str, Any]:
    """Canonicalize wire aliases and SDK v2 Python names for resource metadata."""
    aliases = {
        "uri": ("uri",),
        "uri_template": ("uri_template", "uriTemplate"),
        "mime_type": ("mime_type", "mimeType"),
    }
    schema: dict[str, Any] = {}
    for canonical, names in aliases.items():
        for name in names:
            if name in value:
                schema[canonical] = value.pop(name)
                break
    return schema


def _bounded_descriptor(
    kind: DescriptorKind,
    name: str,
    description: str,
    schema: dict[str, Any],
    metadata: dict[str, Any],
) -> ToolDescriptor:
    """Keep oversized hostile metadata out of reports, rules, and semantic prompts.

    The MCP SDK must decode a protocol response before we see it, but this
    boundary limits all downstream storage and processing. A truncation record
    preserves a digest and byte counts, and the scan emits MCP-N001 rather than
    silently treating incomplete metadata as an ordinary descriptor.
    """
    original = {
        "kind": kind.value,
        "name": name,
        "description": description,
        "schema": schema,
        "metadata": metadata,
    }
    original_bytes = _json_bytes(original)
    exceeded: list[str] = []

    safe_name = _truncate_text(name, MAX_DESCRIPTOR_NAME_BYTES)
    if safe_name != name:
        exceeded.append("name")
    safe_description = _truncate_text(description, MAX_DESCRIPTOR_DESCRIPTION_BYTES)
    if safe_description != description:
        exceeded.append("description")

    safe_schema = schema
    if len(_json_bytes(schema)) > MAX_DESCRIPTOR_SCHEMA_BYTES:
        exceeded.append("schema")
        safe_schema = _truncation_marker(schema)
    safe_metadata = metadata
    if len(_json_bytes(metadata)) > MAX_DESCRIPTOR_METADATA_BYTES:
        exceeded.append("metadata")
        safe_metadata = _truncation_marker(metadata)

    bounded = {
        "kind": kind.value,
        "name": safe_name,
        "description": safe_description,
        "schema": safe_schema,
        "metadata": safe_metadata,
    }
    if len(original_bytes) > MAX_DESCRIPTOR_TOTAL_BYTES and not exceeded:
        # Component budgets normally make this unreachable. Keep an explicit
        # total guard so a future field addition cannot defeat the envelope.
        exceeded.append("total")
        safe_metadata = _truncation_marker(metadata)
        bounded["metadata"] = safe_metadata

    truncation = None
    if exceeded:
        analyzed_bytes = len(_json_bytes(bounded))
        truncation = DescriptorTruncation(
            exceeded_fields=tuple(exceeded),
            original_bytes=len(original_bytes),
            analyzed_bytes=analyzed_bytes,
            original_sha256=hashlib.sha256(original_bytes).hexdigest(),
        )
    return ToolDescriptor(
        kind=kind,
        name=safe_name,
        description=safe_description,
        schema=safe_schema,
        metadata=safe_metadata,
        truncation=truncation,
    )


def _json_bytes(value: Any) -> bytes:
    serialized = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return serialized.encode("utf-8")


def _truncate_text(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    marker = "\n[TRUNCATED_BY_MCPSENTINEL]\n"
    marker_bytes = marker.encode("utf-8")
    remaining = max(2, max_bytes - len(marker_bytes))
    head_bytes = remaining * 2 // 3
    tail_bytes = remaining - head_bytes
    return (
        encoded[:head_bytes].decode("utf-8", errors="ignore")
        + marker
        + encoded[-tail_bytes:].decode("utf-8", errors="ignore")
    )


def _truncation_marker(value: Any) -> dict[str, object]:
    encoded = _json_bytes(value)
    return {
        "_mcpsentinel_truncated": {
            "original_bytes": len(encoded),
            "original_sha256": hashlib.sha256(encoded).hexdigest(),
        }
    }


@asynccontextmanager
async def _client_for(target: TargetConfig) -> AsyncIterator[Client]:
    """Connect with SDK v2 auto-negotiation over the scanner's hardened transports."""
    if target.transport == "http":
        if not target.url:
            raise DiscoveryError("HTTP targets require a URL.")
        pinned_addresses = await _resolve_http_destination(
            target.url, public_only=target.restrict_to_public_network
        )
        async with _http_client(target.url, pinned_addresses) as http_client:
            transport = streamable_http_client(target.url, http_client=http_client)
            async with Client(transport, mode="auto", cache=None) as client:
                yield client
        return

    if target.transport != "stdio" or not target.command:
        raise DiscoveryError(f"Unsupported target transport: {target.transport!r}")

    environment = _stdio_environment(target)
    parameters = StdioServerParameters(
        command=target.command,
        args=list(target.arguments),
        env=environment,
    )
    async with Client(stdio_client(parameters), mode="auto", cache=None) as client:
        yield client


def _stdio_environment(target: TargetConfig) -> dict[str, str]:
    """Build the child environment without forwarding ambient credentials by default."""
    environment = dict(os.environ) if target.inherit_environment else {
        key: os.environ[key] for key in _SAFE_STDIO_ENVIRONMENT_KEYS if key in os.environ
    }
    if not target.inherit_environment:
        # The MCP SDK adds HOME from its safe-default list unless the caller
        # provides a value. Use a neutral temporary location instead of the
        # scanner user's home, where common credential files are discovered.
        environment["HOME"] = tempfile.gettempdir()
    environment.update(target.environment)
    return environment


def _http_client(
    pinned_url: str | None = None, pinned_addresses: tuple[str, ...] | None = None
) -> httpx2.AsyncClient:
    """Create an egress-constrained client for metadata discovery.

    Scanner targets are untrusted: redirects could bypass an operator's host
    allowlist and ambient proxy settings could unexpectedly receive metadata.
    The SDK accepts a caller-owned client, so these controls apply to every
    HTTP request in the MCP session.
    """
    transport: httpx2.AsyncBaseTransport
    if pinned_url is not None and pinned_addresses is not None:
        parsed = urlparse(pinned_url)
        if not parsed.hostname:
            raise DiscoveryError("HTTP targets require a hostname.")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as error:
            raise DiscoveryError("HTTP target has an invalid port.") from error
        transport = _PinnedAsyncHTTPTransport(parsed.hostname, port, pinned_addresses)
    else:
        transport = httpx2.AsyncHTTPTransport(retries=0)
    return httpx2.AsyncClient(
        headers={"Accept-Encoding": "identity"},
        follow_redirects=False,
        trust_env=False,
        timeout=httpx2.Timeout(
            HTTP_READ_TIMEOUT_SECONDS,
            connect=HTTP_CONNECT_TIMEOUT_SECONDS,
            read=HTTP_READ_TIMEOUT_SECONDS,
            write=HTTP_WRITE_TIMEOUT_SECONDS,
            pool=HTTP_POOL_TIMEOUT_SECONDS,
        ),
        transport=_BoundedResponseTransport(transport, MAX_HTTP_RESPONSE_BYTES),
    )


async def _resolve_http_destination(
    url: str, *, public_only: bool
) -> tuple[str, ...]:
    """Resolve and pin an HTTP destination, optionally rejecting non-public IPs.

    Pinning is applied for every HTTP target, including explicitly trusted
    private networks. The public-only flag controls address policy only; it
    never weakens DNS rebinding protection.
    """
    parsed = urlparse(url)
    if not parsed.hostname:
        raise DiscoveryError("HTTP targets require a hostname.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise DiscoveryError("HTTP target has an invalid port.") from error
    try:
        records = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                parsed.hostname,
                port,
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
    if public_only and non_public:
        raise DiscoveryError(
            "HTTP target resolved to a private or reserved address; set "
            "MCPSENTINEL_ALLOW_PRIVATE_HTTP_TARGETS=true only for a trusted local network."
        )
    return tuple(sorted(addresses))


async def _require_public_http_destination(url: str) -> tuple[str, ...]:
    """Compatibility wrapper for callers requiring public-only resolution."""
    return await _resolve_http_destination(url, public_only=True)


async def _all_pages(client_method: Any, item_field: str) -> list[Any]:
    """Collect a protocol-paginated descriptor list without making tool calls."""
    cursor: str | None = None
    items: list[Any] = []
    for _ in range(MAX_DESCRIPTOR_PAGES):
        response = await client_method(cursor=cursor)
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
            async with _client_for(target) as client:
                capabilities = _as_dict(client.server_capabilities)
                descriptors: list[ToolDescriptor] = []

                if capabilities.get("tools") is not None:
                    tools = await _all_pages(client.list_tools, "tools")
                    descriptors.extend(_descriptor(DescriptorKind.TOOL, tool) for tool in tools)
                if capabilities.get("prompts") is not None:
                    prompts = await _all_pages(client.list_prompts, "prompts")
                    descriptors.extend(
                        _descriptor(DescriptorKind.PROMPT, prompt) for prompt in prompts
                    )
                if capabilities.get("resources") is not None:
                    server_resources = await _all_pages(client.list_resources, "resources")
                    descriptors.extend(
                        _descriptor(DescriptorKind.RESOURCE, resource)
                        for resource in server_resources
                    )
                    # Templates share the resources capability and are optional
                    # in older SDK releases.
                    if hasattr(client, "list_resource_templates"):
                        templates = await _all_pages(
                            client.list_resource_templates, "resourceTemplates"
                        )
                        descriptors.extend(
                            _descriptor(DescriptorKind.RESOURCE_TEMPLATE, item)
                            for item in templates
                        )

                if client.instructions:
                    descriptors.append(
                        _bounded_descriptor(
                            DescriptorKind.SERVER_INSTRUCTIONS,
                            "server_instructions",
                            client.instructions,
                            {},
                            {},
                        )
                    )
                server_info = _as_dict(client.server_info) if client.server_info is not None else {}
                metadata = {
                    "server": server_info,
                    "protocol_version": client.protocol_version,
                    "negotiation": (
                        "server_discover"
                        if client.session.discover_result is not None
                        else "legacy_initialize"
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
