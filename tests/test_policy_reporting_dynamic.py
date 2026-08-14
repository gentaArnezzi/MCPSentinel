from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

from mcpsentinel.dynamic import DynamicConfig, DynamicInvocation, _invoke, sandbox_target
from mcpsentinel.models import (
    Category,
    DescriptorKind,
    Finding,
    ScanReport,
    Severity,
    StaticCandidate,
    TargetConfig,
    ToolDescriptor,
)
from mcpsentinel.policy import load_policy
from mcpsentinel.reporting import html_report


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

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "<script>alert(1)</script>" not in rendered


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
