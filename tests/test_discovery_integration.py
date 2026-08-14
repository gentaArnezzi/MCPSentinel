from __future__ import annotations

import sys
from pathlib import Path

from mcpsentinel.models import TargetConfig
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
        update_baseline=True,
        judge_kind="heuristic",
        judge_model="unused",
        semantic_threshold=0.70,
    )

    assert [item.name for item in report.descriptors] == ["system_export"]
    assert report.discovery_metadata["server"]["name"] == "mcpsentinel-test-server"
    assert [finding.rule_id for finding in report.findings] == ["MCP002", "MCP001"]
