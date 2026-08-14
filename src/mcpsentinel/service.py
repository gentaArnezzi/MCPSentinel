"""Orchestrates the precision-first scan pipeline."""

from __future__ import annotations

from pathlib import Path

from .baseline import BaselineStore, stable_hash
from .discovery import discover
from .dynamic import DynamicConfig, run_dynamic_validation
from .models import Finding, ScanReport, Severity, StaticCandidate, TargetConfig, utc_now
from .policy import load_policy
from .rules import StaticAnalyzer, load_rules
from .semantic import SemanticJudge, build_judge


async def scan(
    target: TargetConfig,
    *,
    rules_path: Path | None,
    policy_path: Path | None,
    baseline_root: Path,
    update_baseline: bool,
    judge_kind: str,
    judge_model: str,
    semantic_threshold: float,
    dynamic_config: DynamicConfig | None = None,
) -> ScanReport:
    """Run discovery → static candidates → semantic triage → baseline diff."""
    rules = load_rules(rules_path)
    policy = load_policy(policy_path)
    judge = build_judge(judge_kind, judge_model)
    descriptors, discovery_metadata = await discover(target)
    store = BaselineStore(baseline_root)
    report = ScanReport(
        target=target,
        descriptors=descriptors,
        findings=[],
        started_at=utc_now(),
        judge=judge.identity,
        discovery_metadata=discovery_metadata,
    )

    analyzer = StaticAnalyzer(rules)
    candidates = analyzer.analyze(descriptors)
    policy_denials = [candidate for candidate in candidates if policy.denies(candidate)]
    report.findings.extend(policy.finding_for_denial(candidate) for candidate in policy_denials)
    semantic_candidates = [
        candidate
        for candidate in candidates
        if not policy.allows(candidate) and candidate not in policy_denials
    ]
    threshold = (
        policy.semantic_threshold if policy.semantic_threshold is not None else semantic_threshold
    )
    report.findings.extend(await _semantic_findings(semantic_candidates, judge, store, threshold))
    comparison = store.compare(target, descriptors)
    report.baseline_state = (
        "missing"
        if not comparison.prior_exists
        else "changed"
        if comparison.findings
        else "unchanged"
    )
    report.findings.extend(comparison.findings)
    if not comparison.prior_exists:
        report.notices.append(
            "No approved baseline exists. Review this scan, then rerun with "
            "--approve-baseline to create one."
        )
    elif comparison.findings:
        report.notices.append(
            "The approved baseline was preserved. Review the change before using "
            "--approve-baseline to accept the new definition."
        )
    if dynamic_config is not None:
        dynamic = await run_dynamic_validation(dynamic_config, report.findings)
        report.dynamic_observations.extend(dynamic.observations)
        report.findings.extend(dynamic.findings)
    report.findings.sort(
        key=lambda finding: (-finding.severity.rank, finding.rule_id, finding.subject_name)
    )

    if update_baseline:
        store.save_snapshot(target, descriptors)
        report.baseline_updated = True
        report.notices.append("The current definition was explicitly approved as the new baseline.")
    fallback_count = getattr(judge, "fallback_count", 0)
    if fallback_count:
        report.notices.append(
            "OpenAI semantic review was unavailable for "
            f"{fallback_count} candidate(s); the offline heuristic was used instead."
        )
    report.complete()
    return report


async def _semantic_findings(
    candidates: list[StaticCandidate],
    judge: SemanticJudge,
    store: BaselineStore,
    threshold: float,
) -> list[Finding]:
    findings: list[Finding] = []
    for candidate in candidates:
        cache_key = stable_hash(
            {
                "judge": judge.identity,
                "rule_id": candidate.rule_id,
                "descriptor": candidate.descriptor,
            }
        )
        verdict = store.load_judgement(cache_key)
        if verdict is None:
            verdict = await judge.assess(candidate)
            if not getattr(judge, "used_fallback_for_last_assessment", False):
                store.save_judgement(cache_key, verdict)
        if not verdict.should_report or verdict.confidence < threshold:
            continue
        findings.append(
            Finding(
                rule_id=candidate.rule_id,
                title=candidate.title,
                category=candidate.category,
                severity=candidate.severity,
                message=candidate.description,
                subject_kind=candidate.descriptor.kind,
                subject_name=candidate.descriptor.name,
                evidence=candidate.evidence,
                confidence=verdict.confidence,
                layers=("static", "semantic"),
                rationale=verdict.rationale,
            )
        )
    return findings


def reaches_fail_threshold(report: ScanReport, threshold: Severity | None) -> bool:
    return threshold is not None and any(
        finding.severity.rank >= threshold.rank for finding in report.findings
    )
