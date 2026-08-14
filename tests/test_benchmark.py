from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpsentinel.benchmark import (
    BenchmarkConfigurationError,
    benchmark_json,
    benchmark_text,
    run_benchmark,
)
from mcpsentinel.semantic import HeuristicJudge


async def test_controlled_dataset_measures_semantic_precision_improvement() -> None:
    dataset = Path(__file__).parents[1] / "datasets" / "vulnerable_by_design" / "manifest.json"

    report = await run_benchmark(dataset, HeuristicJudge(), semantic_threshold=0.70)

    assert report.case_count == 200
    assert report.static.true_positive > 0
    assert report.static.false_positive > 0
    assert report.semantic.true_positive > 0
    assert report.semantic.false_positive <= report.static.false_positive
    assert report.semantic.precision > report.static.precision
    assert "prompt_injection" in report.per_category
    assert "ssrf" in report.per_category
    assert report.provenance_counts == {
        "hand-curated-synthetic": 35,
        "synthetic-template": 165,
    }
    assert len(report.dataset_sha256) == 64
    assert report.scanner_version
    assert report.static_duration_ms >= 0
    assert report.semantic_duration_ms >= 0
    payload = json.loads(benchmark_json(report))
    assert payload["semantic"]["precision"] == 1.0
    assert payload["static"]["false_positive_rate"] > 0
    assert "Semantic findings: precision=1.000" in benchmark_text(report)
    assert "Per category:" in benchmark_text(report)
    assert "Provenance:" in benchmark_text(report)
    assert "Dataset SHA-256:" in benchmark_text(report)


async def test_case_matrix_count_is_validated(tmp_path: Path) -> None:
    dataset = tmp_path / "invalid-matrix.json"
    dataset.write_text(
        json.dumps(
            {
                "case_matrices": [
                    {
                        "id_prefix": "invalid",
                        "name_template": "case_{index}",
                        "description_template": "description",
                        "dimensions": {"variant": ["only-one"]},
                        "expected_count": 2,
                        "expected_rules": [],
                    }
                ]
            }
        )
    )

    with pytest.raises(BenchmarkConfigurationError, match="expected 2 cases"):
        await run_benchmark(dataset, HeuristicJudge(), semantic_threshold=0.70)


async def test_public_metadata_negative_control_reports_only_false_positive_rate() -> None:
    dataset = (
        Path(__file__).parents[1]
        / "datasets"
        / "curated_public_metadata_v2"
        / "manifest.json"
    )

    report = await run_benchmark(dataset, HeuristicJudge(), semantic_threshold=0.70)

    assert report.dataset_version == 2
    assert report.evaluation_scope == "public-metadata-negative-control"
    assert report.case_count == 428
    assert report.labeled_positive_count == 0
    assert report.source_count == 2
    assert report.static_candidate_count == 0
    assert report.semantic_report_count == 0
    assert report.static.false_positive_rate == 0.0
    assert report.semantic.false_positive_rate == 0.0
    assert report.static.precision is None
    assert report.static.recall is None
    assert report.static.f1 is None
    assert "scope: public-metadata-negative-control" in benchmark_text(report)
    assert "precision=n/a recall=n/a f1=n/a" in benchmark_text(report)
    payload = json.loads(benchmark_json(report))
    assert payload["static"]["precision"] is None
    assert payload["static"]["recall"] is None
    assert payload["static"]["false_positive_rate"] == 0.0
