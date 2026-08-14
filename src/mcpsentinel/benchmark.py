"""Reproducible measurements for the controlled scanner regression dataset."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import DescriptorKind, ToolDescriptor, to_primitive
from .rules import StaticAnalyzer, load_rules
from .semantic import SemanticJudge


class BenchmarkConfigurationError(ValueError):
    """The controlled benchmark manifest does not follow its public contract."""


@dataclass(frozen=True)
class ClassificationMetrics:
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 1.0

    @property
    def false_positive_rate(self) -> float:
        denominator = self.false_positive + self.true_negative
        return self.false_positive / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        denominator = self.precision + self.recall
        return 2 * self.precision * self.recall / denominator if denominator else 0.0


@dataclass(frozen=True)
class BenchmarkReport:
    dataset: str
    judge: str
    semantic_threshold: float
    case_count: int
    rule_count: int
    static_candidate_count: int
    semantic_report_count: int
    static_duration_ms: int
    semantic_duration_ms: int
    static: ClassificationMetrics
    semantic: ClassificationMetrics


def _rule_ids(value: Any, *, field: str, case_id: str) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise BenchmarkConfigurationError(
            f"Case {case_id!r} needs {field!r} as a list of non-empty rule IDs."
        )
    return set(value)


def _descriptors_and_truth(
    manifest: dict[str, Any],
) -> tuple[list[ToolDescriptor], dict[str, set[str]]]:
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise BenchmarkConfigurationError("Benchmark manifest needs a non-empty 'cases' list.")

    descriptors: list[ToolDescriptor] = []
    expected_reported: dict[str, set[str]] = {}
    seen_ids: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise BenchmarkConfigurationError("Every benchmark case must be an object.")
        case_id = case.get("id")
        name = case.get("name")
        description = case.get("description")
        if not all(isinstance(value, str) and value for value in (case_id, name, description)):
            raise BenchmarkConfigurationError(
                "Every case needs non-empty id, name, and description fields."
            )
        if case_id in seen_ids:
            raise BenchmarkConfigurationError(
                f"Benchmark manifest has duplicate case id {case_id!r}."
            )
        seen_ids.add(case_id)

        static_rules = _rule_ids(
            case.get("expected_rules"), field="expected_rules", case_id=case_id
        )
        reported_value = case.get("expected_reported_rules")
        if reported_value is None:
            reported_rules = set() if case.get("semantic_outcome") == "safe" else static_rules
        else:
            reported_rules = _rule_ids(
                reported_value, field="expected_reported_rules", case_id=case_id
            )
        if not reported_rules.issubset(static_rules):
            raise BenchmarkConfigurationError(
                f"Case {case_id!r} reports a rule that is absent from expected_rules."
            )
        schema = case.get("schema", {})
        metadata = case.get("metadata", {})
        if not isinstance(schema, dict) or not isinstance(metadata, dict):
            raise BenchmarkConfigurationError(
                f"Case {case_id!r} schema and metadata must be objects."
            )
        descriptors.append(
            ToolDescriptor(
                kind=DescriptorKind.TOOL,
                name=name,
                description=description,
                schema=schema,
                metadata={"benchmark_case_id": case_id, **metadata},
            )
        )
        expected_reported[case_id] = reported_rules
    return descriptors, expected_reported


def _metrics(
    predictions: set[tuple[str, str]],
    expected: dict[str, set[str]],
    rule_ids: set[str],
) -> ClassificationMetrics:
    universe = {(case_id, rule_id) for case_id in expected for rule_id in rule_ids}
    positives = {(case_id, rule_id) for case_id, rules in expected.items() for rule_id in rules}
    if not positives.issubset(universe):
        unknown = sorted(positives - universe)
        raise BenchmarkConfigurationError(f"Dataset refers to unknown rule IDs: {unknown}")
    if not predictions.issubset(universe):
        unknown = sorted(predictions - universe)
        raise BenchmarkConfigurationError(f"Scanner emitted unknown rule IDs: {unknown}")
    return ClassificationMetrics(
        true_positive=len(predictions & positives),
        false_positive=len(predictions - positives),
        true_negative=len((universe - predictions) - positives),
        false_negative=len(positives - predictions),
    )


async def run_benchmark(
    dataset_path: Path,
    judge: SemanticJudge,
    semantic_threshold: float,
    rules_path: Path | None = None,
) -> BenchmarkReport:
    """Measure raw static candidates and semantic findings against controlled ground truth."""
    try:
        manifest = json.loads(dataset_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise BenchmarkConfigurationError(
            f"Could not read benchmark dataset {dataset_path}: {error}"
        ) from error
    except json.JSONDecodeError as error:
        raise BenchmarkConfigurationError(
            f"Benchmark dataset is not valid JSON: {error}"
        ) from error
    if not isinstance(manifest, dict):
        raise BenchmarkConfigurationError("Benchmark dataset root must be a JSON object.")
    if not 0 <= semantic_threshold <= 1:
        raise BenchmarkConfigurationError("Semantic threshold must be from 0 to 1.")

    descriptors, expected_reported = _descriptors_and_truth(manifest)
    rules = load_rules(rules_path)
    analyzer = StaticAnalyzer(rules)
    rule_ids = {rule.id for rule in rules}

    static_started = time.perf_counter()
    candidates = analyzer.analyze(descriptors)
    static_duration_ms = round((time.perf_counter() - static_started) * 1000)
    candidates_by_key = {
        (candidate.descriptor.metadata["benchmark_case_id"], candidate.rule_id): candidate
        for candidate in candidates
    }
    static_predictions = set(candidates_by_key)

    semantic_started = time.perf_counter()
    semantic_predictions: set[tuple[str, str]] = set()
    for key, candidate in candidates_by_key.items():
        verdict = await judge.assess(candidate)
        if verdict.should_report and verdict.confidence >= semantic_threshold:
            semantic_predictions.add(key)
    semantic_duration_ms = round((time.perf_counter() - semantic_started) * 1000)

    return BenchmarkReport(
        dataset=str(dataset_path),
        judge=judge.identity,
        semantic_threshold=semantic_threshold,
        case_count=len(descriptors),
        rule_count=len(rules),
        static_candidate_count=len(static_predictions),
        semantic_report_count=len(semantic_predictions),
        static_duration_ms=static_duration_ms,
        semantic_duration_ms=semantic_duration_ms,
        static=_metrics(static_predictions, expected_reported, rule_ids),
        semantic=_metrics(semantic_predictions, expected_reported, rule_ids),
    )


def benchmark_json(report: BenchmarkReport) -> str:
    return json.dumps(to_primitive(report), indent=2, sort_keys=True) + "\n"


def benchmark_text(report: BenchmarkReport) -> str:
    def summary(name: str, metrics: ClassificationMetrics) -> str:
        return (
            f"{name}: precision={metrics.precision:.3f} recall={metrics.recall:.3f} "
            f"f1={metrics.f1:.3f} false_positive_rate={metrics.false_positive_rate:.3f} "
            f"(TP={metrics.true_positive}, FP={metrics.false_positive}, "
            f"TN={metrics.true_negative}, FN={metrics.false_negative})"
        )

    return "\n".join(
        (
            f"Benchmark dataset: {report.dataset}",
            f"Judge: {report.judge} (threshold {report.semantic_threshold:.2f})",
            f"Cases: {report.case_count}; rules: {report.rule_count}",
            summary("Static candidates", report.static),
            summary("Semantic findings", report.semantic),
            (
                "Timing: "
                f"static={report.static_duration_ms}ms, semantic={report.semantic_duration_ms}ms; "
                f"candidates={report.static_candidate_count}, "
                f"reported={report.semantic_report_count}"
            ),
            "",
        )
    )
