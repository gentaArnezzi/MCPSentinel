import json
from datetime import UTC, datetime

from mcpsentinel.models import Category, DescriptorKind, Finding, ScanReport, Severity, TargetConfig
from mcpsentinel.reporting import sarif_report


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
