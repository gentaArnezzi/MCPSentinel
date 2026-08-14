from __future__ import annotations

import json
import tomllib
from pathlib import Path

from mcpsentinel.models import DescriptorKind, ToolDescriptor
from mcpsentinel.rules import StaticAnalyzer, load_rules
from mcpsentinel.semantic import HeuristicJudge


async def test_vulnerable_by_design_dataset_matches_static_and_semantic_ground_truth() -> None:
    path = Path(__file__).parents[1] / "datasets" / "vulnerable_by_design" / "manifest.json"
    manifest = json.loads(path.read_text())
    analyzer = StaticAnalyzer(load_rules())
    judge = HeuristicJudge()

    for case in manifest["cases"]:
        descriptor = ToolDescriptor(
            kind=DescriptorKind.TOOL,
            name=case["name"],
            description=case["description"],
        )
        candidates = analyzer.analyze([descriptor])
        assert set(case["expected_rules"]).issubset({candidate.rule_id for candidate in candidates})
        if "semantic_outcome" in case:
            candidate = next(
                item for item in candidates if item.rule_id == case["expected_rules"][0]
            )
            assert (await judge.assess(candidate)).label == case["semantic_outcome"]


def test_registry_metadata_is_concrete_and_valid_json() -> None:
    root = Path(__file__).parents[1]
    path = root / "registry" / "server.json"
    metadata = json.loads(path.read_text())
    project = tomllib.loads((root / "pyproject.toml").read_text())

    assert metadata["name"] == "io.github.gentaArnezzi/mcpsentinel"
    assert "YOUR_GITHUB_USERNAME" not in json.dumps(metadata)
    assert metadata["version"] == project["project"]["version"]
    assert metadata["packages"][0]["version"] == project["project"]["version"]
    assert metadata["packages"][0]["registryType"] == "pypi"
    assert metadata["packages"][0]["transport"]["type"] == "stdio"
    assert "<!-- mcp-name: io.github.gentaArnezzi/mcpsentinel -->" in (
        root / "README.md"
    ).read_text()
