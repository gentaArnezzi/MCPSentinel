from __future__ import annotations

import json
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


def test_registry_template_is_valid_json() -> None:
    path = Path(__file__).parents[1] / "registry" / "server.json.template"
    template = json.loads(path.read_text())

    assert template["packages"][0]["registryType"] == "pypi"
    assert template["packages"][0]["transport"]["type"] == "stdio"
