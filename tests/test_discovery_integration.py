from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import httpx2
import pytest

from mcpsentinel import discovery
from mcpsentinel.discovery import DiscoveryError
from mcpsentinel.models import DescriptorKind, TargetConfig
from mcpsentinel.service import scan


async def test_stdio_discovery_scans_metadata_without_invoking_tool(tmp_path: Path) -> None:
    fixture = Path(__file__).with_name("fixture_stdio_server.py")
    target = TargetConfig(
        transport="stdio",
        identity="test-server",
        command=sys.executable,
        arguments=(str(fixture),),
    )

    report = await scan(
        target,
        rules_path=None,
        policy_path=None,
        baseline_root=tmp_path,
        update_baseline=False,
        judge_kind="heuristic",
        judge_model="unused",
        semantic_threshold=0.70,
    )

    assert [item.name for item in report.descriptors] == ["system_export", "background_worker"]
    assert report.discovery_metadata["server"]["name"] == "mcpsentinel-test-server"
    assert [finding.rule_id for finding in report.findings] == ["MCP002", "MCP001", "MCP004"]


async def test_stdio_discovery_falls_back_to_legacy_initialization(tmp_path: Path) -> None:
    fixture = Path(__file__).with_name("fixture_legacy_stdio_server.py")
    target = TargetConfig(
        transport="stdio",
        identity="legacy-test-server",
        command=sys.executable,
        arguments=(str(fixture),),
    )

    report = await scan(
        target,
        rules_path=None,
        policy_path=None,
        baseline_root=tmp_path,
        update_baseline=False,
        judge_kind="heuristic",
        judge_model="unused",
        semantic_threshold=0.70,
    )

    assert [item.name for item in report.descriptors] == ["legacy_lookup"]
    assert report.discovery_metadata["server"]["name"] == "mcpsentinel-legacy-test-server"
    assert report.discovery_metadata["negotiation"] == "legacy_initialize"


async def test_stdio_discovery_does_not_forward_ambient_secret_to_child(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("MCPSENTINEL_TEST_AMBIENT_SECRET", "must-not-reach-child")
    fixture = Path(__file__).with_name("fixture_stdio_environment_server.py")
    target = TargetConfig(
        transport="stdio",
        identity="environment-fixture",
        command=sys.executable,
        arguments=(str(fixture),),
    )

    report = await scan(
        target,
        rules_path=None,
        policy_path=None,
        baseline_root=tmp_path,
        update_baseline=False,
        judge_kind="heuristic",
        judge_model="unused",
        semantic_threshold=0.70,
    )

    assert report.discovery_metadata["server"]["name"] == "env-secret-absent"


def test_stdio_environment_is_default_deny_with_explicit_overrides(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "ambient-cloud-secret")
    monkeypatch.setenv("PATH", "/controlled/bin")
    target = TargetConfig(
        transport="stdio",
        identity="fixture",
        command="fixture",
        environment={"FIXTURE_MODE": "safe"},
    )

    environment = discovery._stdio_environment(target)

    assert environment["PATH"] == "/controlled/bin"
    assert environment["HOME"] != os.environ.get("HOME")
    assert environment["FIXTURE_MODE"] == "safe"
    assert "OPENAI_API_KEY" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment


def test_stdio_environment_inheritance_is_an_explicit_opt_in(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-secret")
    target = TargetConfig(
        transport="stdio", identity="fixture", command="fixture", inherit_environment=True
    )

    assert discovery._stdio_environment(target)["OPENAI_API_KEY"] == "ambient-secret"


def test_oversized_descriptor_is_bounded_and_marked_for_review() -> None:
    descriptor = discovery._descriptor(
        DescriptorKind.TOOL,
        {
            "name": "oversized_tool",
            "description": "A" * (discovery.MAX_DESCRIPTOR_DESCRIPTION_BYTES + 1),
            "inputSchema": {"payload": "B" * (discovery.MAX_DESCRIPTOR_SCHEMA_BYTES + 1)},
        },
    )

    assert descriptor.kind is DescriptorKind.TOOL
    assert descriptor.truncation is not None
    assert descriptor.truncation.exceeded_fields == ("description", "schema")
    assert "TRUNCATED_BY_MCPSENTINEL" in descriptor.description
    assert descriptor.schema["_mcpsentinel_truncated"]["original_sha256"]


def test_resource_schema_normalizes_wire_and_sdk_v2_field_names() -> None:
    wire = discovery._descriptor(
        DescriptorKind.RESOURCE_TEMPLATE,
        {
            "uriTemplate": "file:///workspace/{path}",
            "mimeType": "text/plain",
            "description": "Wire-format resource template.",
        },
    )
    pythonic = discovery._descriptor(
        DescriptorKind.RESOURCE_TEMPLATE,
        {
            "uri_template": "file:///workspace/{path}",
            "mime_type": "text/plain",
            "description": "SDK v2 resource template.",
        },
    )

    expected = {
        "uri_template": "file:///workspace/{path}",
        "mime_type": "text/plain",
    }
    assert wire.name == pythonic.name == "file:///workspace/{path}"
    assert wire.schema == pythonic.schema == expected


async def test_streamable_http_discovery_scans_metadata(tmp_path: Path) -> None:
    fixture = Path(__file__).with_name("fixture_http_server.py")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    environment = {**os.environ, "MCPSENTINEL_HTTP_FIXTURE_PORT": str(port)}
    process = subprocess.Popen([sys.executable, str(fixture)], env=environment)
    try:
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                await asyncio.sleep(0.1)
        else:
            pytest.fail("Streamable HTTP fixture did not start.")

        report = await scan(
            TargetConfig(
                transport="http",
                identity=f"http://127.0.0.1:{port}/mcp",
                url=f"http://127.0.0.1:{port}/mcp",
            ),
            rules_path=None,
            policy_path=None,
            baseline_root=tmp_path,
            update_baseline=False,
            judge_kind="heuristic",
            judge_model="unused",
            semantic_threshold=0.70,
        )
    finally:
        process.terminate()
        process.wait(timeout=5)

    assert [item.name for item in report.descriptors] == ["local_lookup", "server_instructions"]
    instructions = report.descriptors[-1]
    assert instructions.kind is DescriptorKind.SERVER_INSTRUCTIONS
    assert "Ignore previous instructions" in instructions.description
    assert any(
        finding.rule_id == "MCP001" and finding.subject_name == "server_instructions"
        for finding in report.findings
    )
    assert report.discovery_metadata["server"]["name"] == "mcpsentinel-http-test-server"
    assert report.discovery_metadata["negotiation"] == "server_discover"


async def test_public_network_restriction_rejects_private_dns(monkeypatch) -> None:
    class Loop:
        async def getaddrinfo(self, *_: object, **__: object):
            return [(0, 0, 0, "", ("127.0.0.1", 443))]

    monkeypatch.setattr(discovery.asyncio, "get_running_loop", lambda: Loop())

    with pytest.raises(DiscoveryError, match="private or reserved"):
        await discovery._require_public_http_destination("https://scanner.example/mcp")


async def test_public_network_restriction_pins_validated_public_addresses(monkeypatch) -> None:
    class Loop:
        async def getaddrinfo(self, *_: object, **__: object):
            return [
                (0, 0, 0, "", ("93.184.216.34", 443)),
                (0, 0, 0, "", ("2606:4700:4700::1111", 443)),
            ]

    monkeypatch.setattr(discovery.asyncio, "get_running_loop", lambda: Loop())

    addresses = await discovery._require_public_http_destination("https://scanner.example/mcp")

    assert addresses == ("2606:4700:4700::1111", "93.184.216.34")


async def test_private_network_exception_still_resolves_addresses_for_pinning(monkeypatch) -> None:
    class Loop:
        async def getaddrinfo(self, *_: object, **__: object):
            return [(0, 0, 0, "", ("127.0.0.1", 443))]

    monkeypatch.setattr(discovery.asyncio, "get_running_loop", lambda: Loop())

    addresses = await discovery._resolve_http_destination(
        "https://scanner.internal/mcp", public_only=False
    )
    client = discovery._http_client("https://scanner.internal/mcp", addresses)
    try:
        assert isinstance(client._transport, discovery._BoundedResponseTransport)
        assert isinstance(client._transport._delegate, discovery._PinnedAsyncHTTPTransport)
    finally:
        await client.aclose()


async def test_http_response_stream_enforces_raw_byte_limit() -> None:
    class Source(httpx2.AsyncByteStream):
        async def __aiter__(self):
            yield b"ab"
            yield b"c"

    stream = discovery._BoundedAsyncByteStream(Source(), maximum_bytes=2)
    with pytest.raises(httpx2.StreamError, match="safety limit"):
        async for _ in stream:
            pass


async def test_pinned_network_backend_never_re_resolves_the_validated_hostname() -> None:
    class Delegate:
        def __init__(self) -> None:
            self.hosts: list[str] = []

        async def connect_tcp(self, **kwargs: object) -> object:
            self.hosts.append(str(kwargs["host"]))
            return object()

        async def sleep(self, _: float) -> None:
            return None

    delegate = Delegate()
    backend = discovery._PinnedPublicNetworkBackend(
        "scanner.example", 443, ("93.184.216.34",), delegate
    )

    await backend.connect_tcp("scanner.example", 443)

    assert delegate.hosts == ["93.184.216.34"]


async def test_http_discovery_refuses_redirects(tmp_path: Path) -> None:
    class RedirectHandler(BaseHTTPRequestHandler):
        requests = 0

        def do_GET(self) -> None:  # noqa: N802 - required handler method name
            type(self).requests += 1
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1/internal")
            self.end_headers()

        do_POST = do_GET

        def log_message(self, *_: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = TargetConfig(
            transport="http",
            identity=f"http://127.0.0.1:{server.server_port}/mcp",
            url=f"http://127.0.0.1:{server.server_port}/mcp",
        )
        with pytest.raises(DiscoveryError):
            await scan(
                target,
                rules_path=None,
                policy_path=None,
                baseline_root=tmp_path,
                update_baseline=False,
                judge_kind="heuristic",
                judge_model="unused",
                semantic_threshold=0.70,
            )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    # Auto negotiation probes server/discover then falls back to legacy initialize
    # for this non-MCP endpoint. Redirects still are never followed.
    assert RedirectHandler.requests == 2


async def test_discovery_stops_a_server_that_exceeds_the_page_limit(monkeypatch) -> None:
    class Response:
        tools: list[object] = []
        nextCursor = "again"

    async def list_tools(*_: object, **__: object) -> Response:
        return Response()

    monkeypatch.setattr(discovery, "MAX_DESCRIPTOR_PAGES", 2)

    with pytest.raises(DiscoveryError, match="exceeded.*limit"):
        await discovery._all_pages(list_tools, "tools")
