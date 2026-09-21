"""Orchestrates the precision-first scan pipeline."""

from __future__ import annotations

import asyncio
from hmac import compare_digest
from pathlib import Path

from .baseline import (
    BaselineStore,
    definition_fingerprint,
    duplicate_descriptor_keys,
    stable_hash,
)
from .discovery import discover
from .dynamic import DynamicConfig, run_dynamic_validation
from .models import (
    Category,
    DescriptorKind,
    Finding,
    JudgeVerdict,
    ScanReport,
    Severity,
    StaticCandidate,
    TargetConfig,
    utc_now,
)
from .policy import load_policy
from .rules import StaticAnalyzer, load_rules
from .semantic import (
    SERVER_INSTRUCTION_RULE_ID,
    SemanticJudge,
    build_judge,
    server_instruction_candidates,
)

MAX_SEMANTIC_CONCURRENCY = 4


class BaselineApprovalError(RuntimeError):
    """A baseline approval could not prove it matches the reviewed definition."""


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
    started_at = utc_now()
    if update_baseline:
        raise BaselineApprovalError(
            "Scanning cannot approve a baseline. Review the definition fingerprint, then run "
            "'mcpsentinel baseline approve ... --fingerprint sha256:<fingerprint>'."
        )
    rules = load_rules(rules_path)
    policy = load_policy(policy_path)
    judge = build_judge(judge_kind, judge_model)
    descriptors, discovery_metadata = await discover(target)
    store = BaselineStore(baseline_root)
    report = ScanReport(
        target=target,
        descriptors=descriptors,
        findings=[],
        started_at=started_at,
        judge=judge.identity,
        discovery_metadata=discovery_metadata,
        definition_fingerprint=definition_fingerprint(target, descriptors, discovery_metadata),
    )
    duplicate_findings = _duplicate_descriptor_findings(descriptors)
    report.findings.extend(duplicate_findings)

    analyzer = StaticAnalyzer(rules)
    candidates = analyzer.analyze(descriptors) + server_instruction_candidates(descriptors)
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
    report.findings.extend(_descriptor_limit_findings(descriptors))
    comparison = store.compare(target, descriptors, discovery_metadata)
    if duplicate_findings:
        report.baseline_state = "ambiguous"
        report.findings.extend(
            finding for finding in comparison.findings if finding.rule_id == "MCP-B002"
        )
        report.notices.append(
            "Baseline descriptor comparison was skipped because duplicate descriptor identities "
            "make this catalog ambiguous. Approval is disabled until every identity is unique."
        )
    else:
        report.baseline_state = (
            "reapproval_required"
            if comparison.reapproval_required
            else "missing"
            if not comparison.prior_exists
            else "changed"
            if comparison.findings
            else "unchanged"
        )
        report.findings.extend(comparison.findings)
        if comparison.notice:
            report.notices.append(comparison.notice)
        elif not comparison.prior_exists:
            report.notices.append(
                "No approved baseline exists. Review this scan's definition fingerprint, then use "
                "'mcpsentinel baseline approve ... --fingerprint sha256:<fingerprint>'."
            )
        elif comparison.findings:
            report.notices.append(
                "The approved baseline was preserved. Review the changed definition fingerprint "
                "before approving it with 'mcpsentinel baseline approve'."
            )
    if dynamic_config is not None:
        dynamic = await run_dynamic_validation(dynamic_config, report.findings)
        report.dynamic_observations.extend(dynamic.observations)
        report.findings.extend(dynamic.findings)
    report.findings.sort(
        key=lambda finding: (-finding.severity.rank, finding.rule_id, finding.subject_name)
    )

    fallback_count = getattr(judge, "fallback_count", 0)
    if fallback_count:
        report.notices.append(
            "OpenAI semantic review was unavailable for "
            f"{fallback_count} candidate(s); the offline heuristic was used instead."
        )
    report.complete()
    return report


async def approve_baseline(
    target: TargetConfig,
    *,
    baseline_root: Path,
    reviewed_fingerprint: str,
) -> str:
    """Rediscover and approve only the exact definition a human previously reviewed."""
    expected = _normalise_fingerprint(reviewed_fingerprint)
    descriptors, discovery_metadata = await discover(target)
    duplicates = duplicate_descriptor_keys(descriptors)
    if duplicates:
        raise BaselineApprovalError(
            "Baseline approval refused: the MCP catalog contains duplicate descriptor "
            "identities: " + ", ".join(duplicates) + "."
        )
    current = definition_fingerprint(target, descriptors, discovery_metadata)
    if not compare_digest(current, expected):
        raise BaselineApprovalError(
            "Baseline approval refused: the MCP definition changed after the reviewed scan. "
            f"Reviewed: sha256:{expected}. Current: sha256:{current}."
        )
    BaselineStore(baseline_root).save_snapshot(target, descriptors, discovery_metadata)
    return current


def _normalise_fingerprint(value: str) -> str:
    fingerprint = value.strip().removeprefix("sha256:")
    is_sha256 = len(fingerprint) == 64 and all(
        character in "0123456789abcdef" for character in fingerprint
    )
    if not is_sha256:
        raise BaselineApprovalError(
            "A definition fingerprint must be a 64-character lowercase SHA-256 value."
        )
    return fingerprint


def _descriptor_limit_findings(descriptors) -> list[Finding]:
    """Surface incomplete analysis rather than silently accepting oversized metadata."""
    findings: list[Finding] = []
    for descriptor in descriptors:
        truncation = descriptor.truncation
        if truncation is None:
            continue
        fields = ", ".join(truncation.exceeded_fields)
        findings.append(
            Finding(
                rule_id="MCP-N001",
                title="MCP descriptor exceeds metadata resource limits",
                category=Category.RESOURCE_EXHAUSTION,
                severity=Severity.MEDIUM,
                message=(
                    f"The {descriptor.kind.value} '{descriptor.name}' exceeded the scanner's "
                    "metadata safety limits and was only partially analyzed."
                ),
                subject_kind=descriptor.kind,
                subject_name=descriptor.name,
                evidence=(
                    f"Exceeded fields: {fields}; original={truncation.original_bytes} bytes; "
                    f"analyzed={truncation.analyzed_bytes} bytes; "
                    f"sha256={truncation.original_sha256}.",
                ),
                confidence=0.98,
                layers=("normalization",),
                rationale=(
                    "Review the descriptor at its source before trusting it. The scanner retained "
                    "only bounded excerpts and fingerprints to prevent metadata-driven exhaustion."
                ),
            )
        )
    return findings


def _duplicate_descriptor_findings(descriptors) -> list[Finding]:
    """Reject ambiguous descriptor catalogs before baselining collapses their keys."""
    counts: dict[str, int] = {}
    for descriptor in descriptors:
        counts[descriptor.key] = counts.get(descriptor.key, 0) + 1
    findings: list[Finding] = []
    for key in duplicate_descriptor_keys(descriptors):
        kind, name = key.split(":", maxsplit=1)
        try:
            subject_kind = DescriptorKind(kind)
        except ValueError:
            subject_kind = DescriptorKind.TOOL
        findings.append(
            Finding(
                rule_id="MCP-N002",
                title="Duplicate MCP descriptor identity",
                category=Category.PROTOCOL_INTEGRITY,
                severity=Severity.MEDIUM,
                message=(
                    f"The server returned {counts[key]} definitions for '{key}', making the "
                    "descriptor catalog ambiguous."
                ),
                subject_kind=subject_kind,
                subject_name=name,
                evidence=(f"Duplicate identity: {key}; count={counts[key]}.",),
                confidence=0.99,
                layers=("normalization", "protocol"),
                rationale=(
                    "Descriptor identities must be unique before MCPSentinel can establish an "
                    "exact trusted definition."
                ),
            )
        )
    return findings


async def _semantic_findings(
    candidates: list[StaticCandidate],
    judge: SemanticJudge,
    store: BaselineStore,
    threshold: float,
) -> list[Finding]:
    semaphore = asyncio.Semaphore(MAX_SEMANTIC_CONCURRENCY)

    async def assess_candidate(candidate: StaticCandidate) -> tuple[StaticCandidate, JudgeVerdict]:
        cache_key = stable_hash(
            {
                "judge": getattr(judge, "cache_identity", judge.identity),
                "rule_id": candidate.rule_id,
                "descriptor": candidate.descriptor,
            }
        )
        verdict = store.load_judgement(cache_key)
        if verdict is None:
            async with semaphore:
                verdict = await judge.assess(candidate)
            if judge.can_cache(verdict):
                store.save_judgement(cache_key, verdict)
        return candidate, verdict

    assessed = await asyncio.gather(*(assess_candidate(candidate) for candidate in candidates))
    findings: list[Finding] = []
    for candidate, verdict in assessed:
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
                layers=(
                    ("semantic",)
                    if candidate.rule_id == SERVER_INSTRUCTION_RULE_ID
                    else ("static", "semantic")
                ),
                rationale=verdict.rationale,
            )
        )
    return findings


def reaches_fail_threshold(report: ScanReport, threshold: Severity | None) -> bool:
    return threshold is not None and any(
        finding.severity.rank >= threshold.rank for finding in report.findings
    )
