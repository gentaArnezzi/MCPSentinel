import json
from datetime import UTC, datetime

from mcpsentinel.models import (
    Category,
    DescriptorKind,
    Finding,
    ScanReport,
    Severity,
    TargetConfig,
    ToolDescriptor,
)
from mcpsentinel.reporting import (
    html_report,
    json_report,
    sarif_report,
    terminal_report,
    text_report,
)


def test_sarif_is_a_2_1_0_document() -> None:
    report = ScanReport(
        target=TargetConfig(
            transport="http", identity="http://localhost:8000/mcp", url="http://localhost:8000/mcp"
        ),
        descriptors=[],
        findings=[
            Finding(
                rule_id="MCP001",
                title="Prompt injection",
                category=Category.PROMPT_INJECTION,
                severity=Severity.HIGH,
                message="Untrusted metadata overrides instructions.",
                subject_kind=DescriptorKind.TOOL,
                subject_name="unsafe_tool",
                evidence=("description matched",),
                confidence=0.9,
                layers=("static", "semantic"),
            )
        ],
        started_at=datetime.now(UTC),
    )
    payload = json.loads(sarif_report(report))

    assert payload["version"] == "2.1.0"
    result = payload["runs"][0]["results"][0]
    assert result["ruleId"] == "MCP001"
    assert result["level"] == "error"


def test_reports_redact_stdio_environment_values_and_http_userinfo() -> None:
    secret = "super-secret-value"
    report = ScanReport(
        target=TargetConfig(
            transport="http",
            identity=f"https://developer:{secret}@example.com/mcp",
            url=f"https://developer:{secret}@example.com/mcp",
            environment={"API_KEY": secret},
        ),
        descriptors=[
            ToolDescriptor(
                kind=DescriptorKind.TOOL,
                name="example",
                description="Example",
                metadata={"api_key": secret},
            )
        ],
        findings=[],
        started_at=datetime.now(UTC),
    )

    rendered_reports = (
        json_report(report),
        sarif_report(report),
        html_report(report),
        text_report(report),
    )
    for rendered in rendered_reports:
        assert secret not in rendered
        assert "developer@" not in rendered
        assert "https://example.com/mcp" in rendered


def test_terminal_report_renders_a_branded_human_summary() -> None:
    from io import StringIO

    from rich.console import Console

    report = ScanReport(
        target=TargetConfig(transport="http", identity="https://example.com/mcp"),
        descriptors=[],
        findings=[],
        started_at=datetime.now(UTC),
    )
    stream = StringIO()

    terminal_report(report, Console(file=stream, color_system=None, force_terminal=False))

    assert "MCPSentinel" in stream.getvalue()
    assert "No reportable findings" in stream.getvalue()
