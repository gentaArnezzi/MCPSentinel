from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from mcpsentinel import dynamic
from mcpsentinel.dynamic import (
    DynamicConfig,
    DynamicInvocation,
    _invoke,
    _residual_process_finding,
    _SandboxTelemetry,
    sandbox_target,
)
from mcpsentinel.models import (
    Category,
    DescriptorKind,
    DynamicObservation,
    DynamicStatus,
    Finding,
    ScanReport,
    Severity,
    StaticCandidate,
    TargetConfig,
    ToolDescriptor,
)
from mcpsentinel.policy import load_policy
from mcpsentinel.reporting import html_report, text_report


def _candidate() -> StaticCandidate:
    descriptor = ToolDescriptor(
        kind=DescriptorKind.TOOL,
        name="controlled_document_fetch",
        description="Fetch any user-provided URL.",
    )
    return StaticCandidate(
        rule_id="MCP003",
        title="Unrestricted network request capability",
        category=Category.SSRF,
        severity=Severity.MEDIUM,
        description="Network request candidate.",
        descriptor=descriptor,
        evidence=("test evidence",),
    )


def test_policy_selectors_allow_and_deny(tmp_path) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "allow": [{"rule_id": "MCP003", "subject_pattern": "^controlled_"}],
                "deny": ["MCP002"],
                "semantic_threshold": 0.8,
            }
        )
    )
    policy = load_policy(policy_path)

    assert policy.allows(_candidate())
    assert policy.semantic_threshold == 0.8


def test_html_report_autoescapes_untrusted_target_and_evidence() -> None:
    report = ScanReport(
        target=TargetConfig(transport="http", identity="<script>alert(1)</script>", url="http://x"),
        descriptors=[],
        findings=[
            Finding(
                rule_id="MCP001",
                title="Prompt injection",
                category=Category.PROMPT_INJECTION,
                severity=Severity.HIGH,
                message="Untrusted metadata.",
                subject_kind=DescriptorKind.TOOL,
                subject_name="<img src=x>",
                evidence=("<script>bad</script>",),
                confidence=0.9,
                layers=("static", "semantic"),
            )
        ],
        started_at=datetime.now(UTC),
    )
    report.complete()
    rendered = html_report(report)

    assert "&lt;script&gt;bad&lt;/script&gt;" in rendered
    assert "<script>bad</script>" not in rendered
    assert "http://x" in rendered


def test_sandbox_target_has_no_network_mounts_or_privileges(monkeypatch) -> None:
    monkeypatch.setattr("mcpsentinel.dynamic.shutil.which", lambda _: "/usr/local/bin/docker")
    target = sandbox_target(
        DynamicConfig(
            image="example/mcp-server:latest",
            entrypoint=("python", "-m", "server"),
            invocations=(DynamicInvocation("unsafe_tool", {}),),
        )
    )
    arguments = set(target.arguments)

    assert "--interactive" in arguments
    assert "--network=none" in arguments
    assert "--read-only" in arguments
    assert "--cap-drop=ALL" in arguments
    assert "--security-opt=no-new-privileges" in arguments
    assert not any(argument.startswith("--volume") for argument in arguments)


class _SecretResponseSession:
    async def call_tool(self, _: str, __: dict[str, object]) -> dict[str, object]:
        return {"content": [{"type": "text", "text": "api_key=sk-controlled-test"}]}


def test_dynamic_response_does_not_retain_secret_but_reports_it() -> None:
    observation, finding = asyncio.run(
        _invoke(_SecretResponseSession(), DynamicInvocation("unsafe_tool", {}), 1)
    )

    assert observation.response_digest
    assert finding is not None
    assert finding.rule_id == "MCP-D001"
    assert "sk-controlled-test" not in finding.evidence[0]


def test_dynamic_process_telemetry_reports_only_a_residual_process_count() -> None:
    finding = _residual_process_finding(
        DynamicInvocation("owned_tool", {}),
        _SandboxTelemetry(process_count=1, filesystem_change_count=0),
        _SandboxTelemetry(process_count=2, filesystem_change_count=0),
    )

    assert finding is not None
    assert finding.rule_id == "MCP-D002"
    assert "1 to 2" in finding.evidence[0]


def test_reports_render_dynamic_telemetry_counts_without_process_details() -> None:
    report = ScanReport(
        target=TargetConfig(transport="stdio", identity="owned-fixture", command="fixture"),
        descriptors=[],
        findings=[],
        started_at=datetime.now(UTC),
        dynamic_observations=[
            DynamicObservation(
                tool_name="owned_tool",
                status=DynamicStatus.SUCCESS,
                duration_ms=12,
                process_count_before=1,
                process_count_after=2,
                filesystem_change_count=0,
                filesystem_change_count_before=0,
                filesystem_change_delta=0,
            )
        ],
    )
    report.complete()

    assert "processes=1->2; filesystem_changes=0->0; delta=+0" in text_report(report)
    assert "Filesystem changes" in html_report(report)


async def test_dynamic_validation_uses_a_fresh_sandbox_session_per_invocation(monkeypatch) -> None:
    sessions: list[object] = []

    class Session:
        async def call_tool(self, name: str, _: dict[str, object]) -> dict[str, object]:
            return {"content": [{"type": "text", "text": f"controlled {name}"}]}

    @asynccontextmanager
    async def fake_client_for(_: TargetConfig):
        session = Session()
        sessions.append(session)
        yield session

    monkeypatch.setattr(dynamic, "_client_for", fake_client_for)
    monkeypatch.setattr(dynamic.shutil, "which", lambda _: "/usr/local/bin/docker")
    eligible = [
        Finding(
            rule_id="MCP004",
            title="Command execution",
            category=Category.COMMAND_EXECUTION,
            severity=Severity.HIGH,
            message="test",
            subject_kind=DescriptorKind.TOOL,
            subject_name=name,
            evidence=("test",),
            confidence=0.9,
            layers=("static", "semantic"),
        )
        for name in ("first", "second")
    ]

    result = await dynamic.run_dynamic_validation(
        DynamicConfig(
            image="controlled-fixture:test",
            invocations=(DynamicInvocation("first", {}), DynamicInvocation("second", {})),
        ),
        eligible,
    )

    assert len(sessions) == 2
    assert [item.tool_name for item in result.observations] == ["first", "second"]
