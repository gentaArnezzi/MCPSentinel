from __future__ import annotations

from pathlib import Path

from mcpsentinel.benchmark import benchmark_json, benchmark_text, run_benchmark
from mcpsentinel.semantic import HeuristicJudge


async def test_controlled_dataset_measures_semantic_precision_improvement() -> None:
    dataset = Path(__file__).parents[1] / "datasets" / "vulnerable_by_design" / "manifest.json"

    report = await run_benchmark(dataset, HeuristicJudge(), semantic_threshold=0.70)

    assert report.case_count >= 10
    assert report.static.true_positive > 0
    assert report.static.false_positive > 0
    assert report.semantic.true_positive > 0
    assert report.semantic.false_positive <= report.static.false_positive
    assert report.semantic.precision > report.static.precision
    assert "prompt_injection" in report.per_category
    assert "ssrf" in report.per_category
    assert report.static_duration_ms >= 0
    assert report.semantic_duration_ms >= 0
    assert '"semantic"' in benchmark_json(report)
    assert "Semantic findings: precision=1.000" in benchmark_text(report)
    assert "Per category:" in benchmark_text(report)
