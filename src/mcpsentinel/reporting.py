"""Human, JSON, and SARIF report writers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from .models import Finding, ScanReport, Severity, to_primitive

SARIF_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def json_report(report: ScanReport) -> str:
    return json.dumps(to_primitive(report), indent=2, sort_keys=True) + "\n"


def sarif_report(report: ScanReport) -> str:
    unique_rules = {finding.rule_id: finding for finding in report.findings}
    payload: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCPSentinel",
                        "version": report.scan_version,
                        "rules": [_sarif_rule(finding) for finding in unique_rules.values()],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "target": report.target.identity,
                            "transport": report.target.transport,
                            "judge": report.judge,
                        },
                    }
                ],
                "results": [_sarif_result(finding) for finding in report.findings],
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def text_report(report: ScanReport) -> str:
    counts = ", ".join(f"{level}={count}" for level, count in report.counts.items() if count)
    counts = counts or "no findings"
    lines = [
        f"MCPSentinel scan: {report.target.identity}",
        f"Discovered: {len(report.descriptors)} descriptors | Judge: {report.judge}",
        f"Risk score: {report.risk_score}/100 ({report.risk_level.value})",
        f"Findings: {counts}",
    ]
    for finding in report.findings:
        layers = "+".join(finding.layers)
        lines.extend(
            [
                "",
                f"[{finding.severity.value.upper()}] {finding.rule_id} {finding.title}",
                f"  Subject: {finding.subject_kind.value} {finding.subject_name}",
                f"  Confidence: {finding.confidence:.0%} | Layers: {layers}",
                f"  {finding.message}",
                f"  Evidence: {finding.evidence[0]}",
            ]
        )
        if finding.rationale:
            lines.append(f"  Triage: {finding.rationale}")
    return "\n".join(lines) + "\n"


def html_report(report: ScanReport) -> str:
    """Render a self-contained, autoescaped visual report from scanner-owned data."""
    environment = Environment(
        loader=PackageLoader("mcpsentinel", "templates"),
        autoescape=select_autoescape(["html", "htm", "xml"]),
    )
    template = environment.get_template("risk_report.html")
    return template.render(
        report=to_primitive(report),
        counts=report.counts,
        risk_score=report.risk_score,
        risk_level=report.risk_level.value,
    )


def write_report(report: ScanReport, format_name: str, output: Path | None) -> str:
    writers = {"text": text_report, "json": json_report, "sarif": sarif_report, "html": html_report}
    rendered = writers[format_name](report)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    return rendered


def _sarif_rule(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.message},
        "defaultConfiguration": {"level": SARIF_LEVELS[finding.severity]},
        "properties": {"category": finding.category.value, "severity": finding.severity.value},
    }


def _sarif_result(finding: Finding) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "level": SARIF_LEVELS[finding.severity],
        "message": {
            "text": f"{finding.subject_kind.value} '{finding.subject_name}': {finding.message}"
        },
        "properties": {
            "category": finding.category.value,
            "severity": finding.severity.value,
            "subject_kind": finding.subject_kind.value,
            "subject_name": finding.subject_name,
            "confidence": finding.confidence,
            "layers": list(finding.layers),
            "evidence": list(finding.evidence),
            "rationale": finding.rationale,
        },
    }
