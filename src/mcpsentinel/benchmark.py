"""Reproducible measurements for the controlled scanner regression dataset."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Any

from . import __version__
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
    def precision(self) -> float | None:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else None

    @property
    def recall(self) -> float | None:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else None

    @property
    def false_positive_rate(self) -> float | None:
        denominator = self.false_positive + self.true_negative
        return self.false_positive / denominator if denominator else None

    @property
    def f1(self) -> float | None:
        precision = self.precision
        recall = self.recall
        if precision is None or recall is None:
            return None
        denominator = precision + recall
        return 2 * precision * recall / denominator if denominator else 0.0


@dataclass(frozen=True)
class BenchmarkReport:
    dataset: str
    dataset_sha256: str
    dataset_version: int
    evaluation_scope: str
    scanner_version: str
    judge: str
    semantic_threshold: float
    case_count: int
    labeled_positive_count: int
    source_count: int
    rule_count: int
    static_candidate_count: int
    semantic_report_count: int
    static_duration_ms: int
    semantic_duration_ms: int
    static: ClassificationMetrics
    semantic: ClassificationMetrics
    per_category: dict[str, CategoryMetrics]
    provenance_counts: dict[str, int]


@dataclass(frozen=True)
class CategoryMetrics:
    """Static and semantic results for one attack category."""

    static: ClassificationMetrics
    semantic: ClassificationMetrics


@dataclass(frozen=True)
class BenchmarkDatasetMetadata:
    """Validated dataset-level context required to interpret benchmark metrics."""

    version: int
    evaluation_scope: str
    source_count: int


def _rule_ids(value: Any, *, field: str, case_id: str) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise BenchmarkConfigurationError(
            f"Case {case_id!r} needs {field!r} as a list of non-empty rule IDs."
        )
    return set(value)


def _descriptors_and_truth(
    manifest: dict[str, Any],
) -> tuple[list[ToolDescriptor], dict[str, set[str]], dict[str, str]]:
    cases = _expanded_cases(manifest)

    descriptors: list[ToolDescriptor] = []
    expected_reported: dict[str, set[str]] = {}
    provenance_by_case: dict[str, str] = {}
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
        provenance = case.get("provenance", "hand-curated-synthetic")
        if not isinstance(provenance, str) or not provenance:
            raise BenchmarkConfigurationError(
                f"Case {case_id!r} needs a non-empty provenance string."
            )

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
        try:
            kind = DescriptorKind(case.get("kind", DescriptorKind.TOOL.value))
        except ValueError as error:
            raise BenchmarkConfigurationError(
                f"Case {case_id!r} has an unsupported descriptor kind."
            ) from error
        descriptors.append(
            ToolDescriptor(
                kind=kind,
                name=name,
                description=description,
                schema=schema,
                metadata={"benchmark_case_id": case_id, **metadata},
            )
        )
        expected_reported[case_id] = reported_rules
        provenance_by_case[case_id] = provenance
    return descriptors, expected_reported, provenance_by_case


def _dataset_metadata(manifest: dict[str, Any]) -> BenchmarkDatasetMetadata:
    version = manifest.get("version", 1)
    if not isinstance(version, int) or version < 1:
        raise BenchmarkConfigurationError("Benchmark dataset version must be a positive integer.")
    if version == 1:
        return BenchmarkDatasetMetadata(
            version=version,
            evaluation_scope="controlled-synthetic-regression",
            source_count=0,
        )
    if version not in {2, 3}:
        raise BenchmarkConfigurationError(f"Unsupported benchmark dataset version {version}.")

    evaluation_scope = manifest.get("evaluation_scope")
    scopes = {
        2: "public-metadata-negative-control",
        3: "authorized-metadata-positive-control",
    }
    if evaluation_scope != scopes[version]:
        raise BenchmarkConfigurationError(
            f"Version {version} benchmark datasets require the {scopes[version]} scope."
        )
    if manifest.get("case_matrices", []):
        raise BenchmarkConfigurationError(
            f"Version {version} source-attributed datasets must contain literal cases, "
            "not generated case matrices."
        )
    labeling = manifest.get("labeling")
    if not isinstance(labeling, dict) or not all(
        isinstance(labeling.get(field), str) and labeling[field]
        for field in ("rubric", "review_status")
    ):
        raise BenchmarkConfigurationError(
            f"Version {version} benchmark datasets require non-empty labeling rubric and review "
            "status."
        )
    if not isinstance(labeling.get("reviewer_count"), int) or labeling["reviewer_count"] < 1:
        raise BenchmarkConfigurationError(
            f"Version {version} benchmark datasets require a positive labeling reviewer_count."
        )

    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        raise BenchmarkConfigurationError(
            f"Version {version} benchmark datasets require source records."
        )
    source_ids: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            raise BenchmarkConfigurationError(
                f"Every Version {version} source record must be an object."
            )
        source_id = source.get("id")
        if not isinstance(source_id, str) or not source_id or source_id in source_ids:
            raise BenchmarkConfigurationError(
                f"Version {version} source IDs must be unique non-empty strings."
            )
        source_ids.add(source_id)
        if not all(
            isinstance(source.get(field), str) and source[field]
            for field in ("repository", "license", "license_path", "extraction")
        ):
            raise BenchmarkConfigurationError(
                f"Version {version} source {source_id!r} has incomplete provenance metadata."
            )
        commit = source.get("commit")
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise BenchmarkConfigurationError(
                f"Version {version} source {source_id!r} must pin a full Git commit SHA."
            )
        if not isinstance(source.get("case_count"), int) or source["case_count"] < 1:
            raise BenchmarkConfigurationError(
                f"Version {version} source {source_id!r} needs a positive case_count."
        )
        if version == 3 and (
            not isinstance(source.get("authorization"), str) or not source["authorization"]
        ):
            raise BenchmarkConfigurationError(
                f"Version 3 source {source_id!r} requires an authorization statement."
            )

    cases = manifest.get("cases", [])
    if not isinstance(cases, list) or not cases:
        raise BenchmarkConfigurationError(
            f"Version {version} benchmark datasets require literal cases."
        )
    source_case_counts = {source["id"]: 0 for source in sources}
    for case in cases:
        if not isinstance(case, dict):
            raise BenchmarkConfigurationError(
                f"Every Version {version} benchmark case must be an object."
            )
        provenance = {
            2: "source-attributed-public-metadata",
            3: "source-attributed-authorized-positive-control",
        }[version]
        if case.get("provenance") != provenance:
            raise BenchmarkConfigurationError(
                f"Version {version} cases must use {provenance} provenance."
            )
        expected_rules = case.get("expected_rules")
        expected_reported_rules = case.get("expected_reported_rules")
        if version == 2 and (expected_rules or expected_reported_rules):
            raise BenchmarkConfigurationError(
                "Public-metadata negative-control cases must not label ordinary tool metadata "
                "as an unbounded-risk finding."
            )
        if version == 3 and (
            not isinstance(expected_rules, list)
            or not expected_rules
            or not isinstance(expected_reported_rules, list)
            or not expected_reported_rules
        ):
            raise BenchmarkConfigurationError(
                "Authorized positive-control cases require non-empty expected rule labels."
            )
        source = case.get("source")
        if not isinstance(source, dict) or source.get("source_id") not in source_case_counts:
            raise BenchmarkConfigurationError(
                f"Version {version} cases must name a declared source record."
            )
        if not isinstance(source.get("path"), str) or not source["path"]:
            raise BenchmarkConfigurationError(
                f"Version {version} cases require a non-empty source path."
            )
        if not isinstance(source.get("line"), int) or source["line"] < 1:
            raise BenchmarkConfigurationError(
                f"Version {version} cases require a positive source line."
            )
        digest = source.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise BenchmarkConfigurationError(
                f"Version {version} cases require a source-file SHA-256."
            )
        if version == 3 and (
            not isinstance(source.get("source_label"), str) or not source["source_label"]
        ):
            raise BenchmarkConfigurationError(
                "Authorized positive-control cases require a source-authored label."
            )
        source_case_counts[source["source_id"]] += 1
    for source in sources:
        if source_case_counts[source["id"]] != source["case_count"]:
            raise BenchmarkConfigurationError(
                f"Version 2 source {source['id']!r} declares {source['case_count']} cases, "
                f"but {source_case_counts[source['id']]} were found."
            )
    return BenchmarkDatasetMetadata(
        version=version,
        evaluation_scope=evaluation_scope,
        source_count=len(sources),
    )


def _expanded_cases(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Materialize hand-curated cases and transparent deterministic case matrices."""
    cases = manifest.get("cases", [])
    if not isinstance(cases, list):
        raise BenchmarkConfigurationError("Benchmark 'cases' must be a list.")
    expanded: list[dict[str, Any]] = list(cases)
    matrices = manifest.get("case_matrices", [])
    if not isinstance(matrices, list):
        raise BenchmarkConfigurationError("Benchmark 'case_matrices' must be a list.")
    for matrix in matrices:
        if not isinstance(matrix, dict):
            raise BenchmarkConfigurationError("Every benchmark case matrix must be an object.")
        prefix = matrix.get("id_prefix")
        name_template = matrix.get("name_template")
        description_template = matrix.get("description_template")
        dimensions = matrix.get("dimensions", {})
        if not all(isinstance(value, str) and value for value in (prefix, name_template)):
            raise BenchmarkConfigurationError(
                "Every benchmark case matrix needs non-empty id_prefix and name_template."
            )
        if not isinstance(description_template, str):
            raise BenchmarkConfigurationError(
                f"Benchmark matrix {prefix!r} needs a string description_template."
            )
        if not isinstance(dimensions, dict) or not all(
            isinstance(key, str)
            and key
            and isinstance(values, list)
            and values
            and all(isinstance(value, (str, int, float)) for value in values)
            for key, values in dimensions.items()
        ):
            raise BenchmarkConfigurationError(
                f"Benchmark matrix {prefix!r} needs non-empty list dimensions."
            )
        dimension_names = tuple(sorted(dimensions))
        combinations = tuple(product(*(dimensions[name] for name in dimension_names)))
        expected_count = matrix.get("expected_count", len(combinations))
        if expected_count != len(combinations):
            raise BenchmarkConfigurationError(
                f"Benchmark matrix {prefix!r} expected {expected_count} cases, "
                f"but its dimensions generate {len(combinations)}."
            )
        for index, combination in enumerate(combinations, start=1):
            values = {
                "id_prefix": prefix,
                "index": index,
                **dict(zip(dimension_names, combination, strict=True)),
            }
            case = {
                key: _render_template(value, values)
                for key, value in matrix.items()
                if key
                not in {
                    "id_prefix",
                    "name_template",
                    "description_template",
                    "dimensions",
                    "expected_count",
                }
            }
            case.update(
                {
                    "id": f"{prefix}-{index:03d}",
                    "name": _render_template(name_template, values),
                    "description": _render_template(description_template, values),
                    "provenance": matrix.get("provenance", "synthetic-template"),
                }
            )
            expanded.append(case)
    if not expanded:
        raise BenchmarkConfigurationError(
            "Benchmark manifest needs at least one case or case matrix."
        )
    return expanded


def _render_template(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, str):
        try:
            return value.format(**variables)
        except KeyError as error:
            raise BenchmarkConfigurationError(
                f"Benchmark template refers to an unknown variable {error.args[0]!r}."
            ) from error
    if isinstance(value, list):
        return [_render_template(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: _render_template(item, variables) for key, item in value.items()}
    return value


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
        dataset_bytes = dataset_path.read_bytes()
        manifest = json.loads(dataset_bytes)
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

    metadata = _dataset_metadata(manifest)
    descriptors, expected_reported, provenance_by_case = _descriptors_and_truth(manifest)
    rules = load_rules(rules_path)
    analyzer = StaticAnalyzer(rules)
    rule_ids = {rule.id for rule in rules}
    category_rule_ids: dict[str, set[str]] = {}
    for rule in rules:
        category_rule_ids.setdefault(rule.category.value, set()).add(rule.id)

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
        dataset_sha256=hashlib.sha256(dataset_bytes).hexdigest(),
        dataset_version=metadata.version,
        evaluation_scope=metadata.evaluation_scope,
        scanner_version=__version__,
        judge=judge.identity,
        semantic_threshold=semantic_threshold,
        case_count=len(descriptors),
        labeled_positive_count=sum(len(rule_ids) for rule_ids in expected_reported.values()),
        source_count=metadata.source_count,
        rule_count=len(rules),
        static_candidate_count=len(static_predictions),
        semantic_report_count=len(semantic_predictions),
        static_duration_ms=static_duration_ms,
        semantic_duration_ms=semantic_duration_ms,
        static=_metrics(static_predictions, expected_reported, rule_ids),
        semantic=_metrics(semantic_predictions, expected_reported, rule_ids),
        per_category={
            category: CategoryMetrics(
                static=_metrics(
                    {item for item in static_predictions if item[1] in category_rules},
                    {
                        case_id: rules & category_rules
                        for case_id, rules in expected_reported.items()
                    },
                    category_rules,
                ),
                semantic=_metrics(
                    {item for item in semantic_predictions if item[1] in category_rules},
                    {
                        case_id: rules & category_rules
                        for case_id, rules in expected_reported.items()
                    },
                    category_rules,
                ),
            )
            for category, category_rules in sorted(category_rule_ids.items())
        },
        provenance_counts={
            provenance: sum(item == provenance for item in provenance_by_case.values())
            for provenance in sorted(set(provenance_by_case.values()))
        },
    )


def benchmark_json(report: BenchmarkReport) -> str:
    def metrics_payload(metrics: ClassificationMetrics) -> dict[str, int | float | None]:
        return {
            **to_primitive(metrics),
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1,
            "false_positive_rate": metrics.false_positive_rate,
        }

    payload = to_primitive(report)
    payload["static"] = metrics_payload(report.static)
    payload["semantic"] = metrics_payload(report.semantic)
    payload["per_category"] = {
        category: {
            "static": metrics_payload(metrics.static),
            "semantic": metrics_payload(metrics.semantic),
        }
        for category, metrics in report.per_category.items()
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def benchmark_text(report: BenchmarkReport) -> str:
    def summary(name: str, metrics: ClassificationMetrics) -> str:
        def value(metric: float | None) -> str:
            return f"{metric:.3f}" if metric is not None else "n/a"

        return (
            f"{name}: precision={value(metrics.precision)} recall={value(metrics.recall)} "
            f"f1={value(metrics.f1)} false_positive_rate={value(metrics.false_positive_rate)} "
            f"(TP={metrics.true_positive}, FP={metrics.false_positive}, "
            f"TN={metrics.true_negative}, FN={metrics.false_negative})"
        )

    categories = tuple(
        f"  {category}: {summary('static', metrics.static)}; "
        f"{summary('semantic', metrics.semantic)}"
        for category, metrics in report.per_category.items()
    )
    return "\n".join(
        (
            f"Benchmark dataset: {report.dataset}",
            f"Dataset SHA-256: {report.dataset_sha256}",
            f"Dataset version: {report.dataset_version}; scope: {report.evaluation_scope}",
            f"Scanner: MCPSentinel {report.scanner_version}",
            f"Judge: {report.judge} (threshold {report.semantic_threshold:.2f})",
            (
                f"Cases: {report.case_count}; rules: {report.rule_count}; "
                f"labelled positive pairs: {report.labeled_positive_count}; "
                f"source records: {report.source_count}"
            ),
            summary("Static candidates", report.static),
            summary("Semantic findings", report.semantic),
            "Provenance: "
            + ", ".join(
                f"{provenance}={count}"
                for provenance, count in report.provenance_counts.items()
            ),
            "Per category:",
            *categories,
            (
                "Timing: "
                f"static={report.static_duration_ms}ms, semantic={report.semantic_duration_ms}ms; "
                f"candidates={report.static_candidate_count}, "
                f"reported={report.semantic_report_count}"
            ),
            "",
        )
    )
