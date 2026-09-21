"""Exercise the documented onboarding against a real metadata-only MCP process."""

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


def cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "mcpsentinel.cli", *arguments],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=ROOT,
    )


@pytest.mark.parametrize("scenario", ["clean", "review", "duplicate"])
def test_demo_scan_review_approval_and_report(tmp_path: Path, scenario: str) -> None:
    target = shlex.join(
        [sys.executable, str(ROOT / "examples/demo_server.py"), "--scenario", scenario]
    )
    scope = [target, "--transport", "stdio", "--baseline-dir", str(tmp_path / "baseline")]
    result = cli("scan", *scope, "--format", "json", "--fail-on", "high")
    assert result.returncode == (1 if scenario == "review" else 0), result.stderr
    report = json.loads(result.stdout)
    assert "\x1b" not in result.stdout
    assert report["baseline_state"] == ("ambiguous" if scenario == "duplicate" else "missing")
    rules = {finding["rule_id"] for finding in report["findings"]}
    if scenario == "clean":
        assert not rules
    elif scenario == "review":
        assert "MCP-S001" in rules
    else:
        assert "MCP-N002" in rules

    fingerprint = report["definition_fingerprint"]
    # A stale/wrong review can never create a trust snapshot.
    rejected = cli("baseline", "approve", *scope, "--fingerprint", "0" * 64)
    assert rejected.returncode == 2
    assert not list((tmp_path / "baseline" / "baselines").glob("*.json"))
    approval = cli("baseline", "approve", *scope, "--fingerprint", fingerprint)
    if scenario == "duplicate":
        assert approval.returncode == 2
        assert "duplicate" in approval.stderr.lower()
        assert not list((tmp_path / "baseline" / "baselines").glob("*.json"))
    else:
        assert approval.returncode == 0, approval.stderr
        repeat = cli("scan", *scope, "--format", "json")
        assert json.loads(repeat.stdout)["baseline_state"] == "unchanged"

    html = tmp_path / "report.html"
    rendered = cli("scan", *scope, "--format", "html", "--output", str(html))
    assert rendered.returncode == 0, rendered.stderr
    content = html.read_text()
    assert "{{ report." not in content
    assert "{% " not in content
    assert "MCPSentinel" in content
    assert fingerprint in content


def test_benchmark_creates_output_directory_and_reports_io_errors(tmp_path: Path) -> None:
    dataset = str(ROOT / "datasets/server_instructions_v4/manifest.json")
    output = tmp_path / "nested" / "benchmark.json"
    result = cli("benchmark", dataset, "--format", "json", "--output", str(output))
    assert result.returncode == 0, result.stderr
    assert json.loads(output.read_text())["case_count"] == 28
    blocked = cli("benchmark", dataset, "--output", str(tmp_path))
    assert blocked.returncode == 2
    assert "mcpsentinel: error:" in blocked.stderr
    assert "Traceback" not in blocked.stderr
