from __future__ import annotations

import json
import tomllib
from pathlib import Path

from mcpsentinel.benchmark import _expanded_cases
from mcpsentinel.models import DescriptorKind, ToolDescriptor
from mcpsentinel.rules import StaticAnalyzer, load_rules
from mcpsentinel.semantic import HeuristicJudge


async def test_vulnerable_by_design_dataset_matches_static_and_semantic_ground_truth() -> None:
    path = Path(__file__).parents[1] / "datasets" / "vulnerable_by_design" / "manifest.json"
    manifest = json.loads(path.read_text())
    analyzer = StaticAnalyzer(load_rules())
    judge = HeuristicJudge()

    cases = _expanded_cases(manifest)
    assert len(cases) == 200

    for case in cases:
        descriptor = ToolDescriptor(
            kind=DescriptorKind(case.get("kind", DescriptorKind.TOOL.value)),
            name=case["name"],
            description=case["description"],
            schema=case.get("schema", {}),
            metadata=case.get("metadata", {}),
        )
        candidates = analyzer.analyze([descriptor])
        if "semantic_outcome" in case and case["expected_rules"]:
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
    assert project["project"]["name"] == "mcp-guardian-scan"
    assert metadata["version"] == project["project"]["version"]
    assert metadata["packages"][0]["version"] == project["project"]["version"]
    assert metadata["packages"][0]["registryType"] == "pypi"
    assert metadata["packages"][0]["identifier"] == project["project"]["name"]
    assert metadata["packages"][0]["transport"]["type"] == "stdio"
    assert "<!-- mcp-name: io.github.gentaArnezzi/mcpsentinel -->" in (
        root / "README.md"
    ).read_text()
    workflow = (root / ".github" / "workflows" / "publish.yml").read_text()
    assert "id-token: write" in workflow
    assert "name: pypi" in workflow
    assert "./mcp-publisher publish registry/server.json" in workflow


def test_curated_public_metadata_dataset_has_pinned_sources_and_literal_cases() -> None:
    root = Path(__file__).parents[1]
    manifest = json.loads(
        (root / "datasets" / "curated_public_metadata_v2" / "manifest.json").read_text()
    )

    assert manifest["version"] == 2
    assert manifest["evaluation_scope"] == "public-metadata-negative-control"
    assert "case_matrices" not in manifest
    assert len(manifest["cases"]) == 428
    assert manifest["labeling"]["reviewer_count"] == 1
    assert manifest["labeling"]["review_status"] == (
        "maintainer-reviewed; independent-review-pending"
    )
    source_summary = [
        (source["id"], source["case_count"], source["license"])
        for source in manifest["sources"]
    ]
    assert source_summary == [
        ("aws", 329, "Apache-2.0"),
        ("github", 99, "MIT"),
    ]

    source_counts = {source["id"]: 0 for source in manifest["sources"]}
    for case in manifest["cases"]:
        assert case["provenance"] == "source-attributed-public-metadata"
        assert case["expected_rules"] == []
        assert case["expected_reported_rules"] == []
        assert case["source"]["source_id"] in source_counts
        assert case["source"]["line"] > 0
        assert len(case["source"]["sha256"]) == 64
        source_counts[case["source"]["source_id"]] += 1
    assert source_counts == {"aws": 329, "github": 99}
