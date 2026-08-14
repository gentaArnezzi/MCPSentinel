"""Optional end-to-end proof for the Docker dynamic-validation boundary."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from mcpsentinel.dynamic import DynamicConfig, DynamicInvocation
from mcpsentinel.models import TargetConfig
from mcpsentinel.service import scan

RUN_DOCKER_TESTS = os.environ.get("MCPSENTINEL_RUN_DOCKER_TESTS") == "1"


@pytest.mark.skipif(
    not RUN_DOCKER_TESTS or shutil.which("docker") is None,
    reason="Set MCPSENTINEL_RUN_DOCKER_TESTS=1 to run the Docker sandbox integration test.",
)
async def test_dynamic_validation_uses_a_real_network_isolated_container(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    fixture_dir = root / "tests" / "docker_dynamic_fixture"
    image = "mcpsentinel-dynamic-fixture:test"
    subprocess.run(
        [
            "docker",
            "build",
            "--pull=false",
            "--tag",
            image,
            "--file",
            str(fixture_dir / "Dockerfile"),
            str(fixture_dir),
        ],
        check=True,
    )
    report = await scan(
        TargetConfig(
            transport="stdio",
            identity="controlled-host-fixture",
            command=sys.executable,
            arguments=(str(root / "tests" / "fixture_stdio_server.py"),),
        ),
        rules_path=None,
        policy_path=None,
        baseline_root=tmp_path / "baselines",
        update_baseline=False,
        judge_kind="heuristic",
        judge_model="gpt-4o-mini",
        semantic_threshold=0.70,
        dynamic_config=DynamicConfig(
            image=image,
            invocations=(
                DynamicInvocation("system_export", {}),
                DynamicInvocation("background_worker", {}),
            ),
            confidence_threshold=0.70,
        ),
    )

    secret_observation = next(
        item for item in report.dynamic_observations if item.tool_name == "system_export"
    )
    worker_observation = next(
        item for item in report.dynamic_observations if item.tool_name == "background_worker"
    )
    assert secret_observation.status == "success"
    assert secret_observation.response_digest
    assert worker_observation.process_count_before is not None
    assert worker_observation.process_count_after is not None
    assert worker_observation.process_count_after > worker_observation.process_count_before
    assert worker_observation.filesystem_change_count is not None
    assert any(finding.rule_id == "MCP-D001" for finding in report.findings)
    assert any(finding.rule_id == "MCP-D002" for finding in report.findings)
