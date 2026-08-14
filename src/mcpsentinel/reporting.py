"""Human, JSON, and SARIF report writers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import Finding, ScanReport, Severity
from .safety import safe_report_payload, safe_target_identity, sanitize_text, sanitize_value

SARIF_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def json_report(report: ScanReport) -> str:
    return json.dumps(safe_report_payload(report), indent=2, sort_keys=True) + "\n"


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
                            "target": safe_target_identity(report.target),
                            "transport": report.target.transport,
                            "judge": report.judge,
                            "baseline_state": report.baseline_state,
                            "notices": report.notices,
                        },
                    }
                ],
                "results": [_sarif_result(finding) for finding in report.findings],
            }
        ],
    }
    return json.dumps(sanitize_value(payload), indent=2, sort_keys=True) + "\n"


def text_report(report: ScanReport) -> str:
    counts = ", ".join(f"{level}={count}" for level, count in report.counts.items() if count)
    counts = counts or "no findings"
    lines = [
        f"MCPSentinel scan: {safe_target_identity(report.target)}",
        f"Discovered: {len(report.descriptors)} descriptors | Judge: {report.judge}",
        (
            f"Baseline: {report.baseline_state}"
            + (" | explicitly approved" if report.baseline_updated else "")
        ),
        f"Risk score: {report.risk_score}/100 ({report.risk_level.value})",
        f"Findings: {counts}",
    ]
    if report.notices:
        lines.extend(["", "Notes:"])
        lines.extend(f"- {notice}" for notice in report.notices)
    if report.dynamic_observations:
        lines.extend(["", "Dynamic sandbox observations:"])
        for observation in report.dynamic_observations:
            process_counts = (
                "n/a"
                if observation.process_count_before is None
                or observation.process_count_after is None
                else f"{observation.process_count_before}->{observation.process_count_after}"
            )
            filesystem_changes = (
                "n/a"
                if observation.filesystem_change_count is None
                else (
                    f"{observation.filesystem_change_count_before}"
                    f"->{observation.filesystem_change_count}; "
                    f"delta={observation.filesystem_change_delta:+d}"
                    if observation.filesystem_change_count_before is not None
                    and observation.filesystem_change_delta is not None
                    else str(observation.filesystem_change_count)
                )
            )
            if observation.filesystem_telemetry_truncated:
                filesystem_changes += " (truncated)"
            lines.append(
                f"- {observation.tool_name}: {observation.status}; "
                f"{observation.duration_ms} ms; processes={process_counts}; "
                f"filesystem_changes={filesystem_changes}"
            )
    for finding in report.findings:
        layers = "+".join(finding.layers)
        lines.extend(
            [
                "",
                f"[{finding.severity.value.upper()}] {finding.rule_id} {finding.title}",
                f"  Subject: {finding.subject_kind.value} {sanitize_text(finding.subject_name)}",
                f"  Confidence: {finding.confidence:.0%} | Layers: {layers}",
                f"  {sanitize_text(finding.message)}",
                f"  Evidence: {sanitize_text(finding.evidence[0])}",
            ]
        )
        if finding.rationale:
            lines.append(f"  Triage: {sanitize_text(finding.rationale)}")
    return "\n".join(lines) + "\n"


def terminal_report(report: ScanReport, console: Console | None = None) -> None:
    """Render a human-first terminal summary without changing file report formats."""
    console = console or Console()
    target = safe_target_identity(report.target)
    console.print(
        Panel.fit(
            Text.assemble(
                ("MCPSentinel", "bold cyan"),
                "  •  MCP Security Scanner\n",
                (target, "bold"),
                "\nRead-only metadata discovery",
            ),
            border_style="cyan",
            padding=(0, 2),
        )
    )
    summary = Table.grid(expand=False, padding=(0, 2))
    summary.add_column(style="dim")
    summary.add_column()
    summary.add_row("Discovered", f"{len(report.descriptors)} descriptors")
    summary.add_row("Judge", report.judge)
    summary.add_row(
        "Baseline",
        report.baseline_state + (" (approved)" if report.baseline_updated else ""),
    )
    summary.add_row("Risk score", f"{report.risk_score}/100 ({report.risk_level.value})")
    console.print(summary)

    if report.findings:
        table = Table(title="Findings", box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("Severity", style="bold", no_wrap=True)
        table.add_column("Subject", style="cyan", overflow="fold")
        table.add_column("Finding", overflow="fold")
        table.add_column("Confidence", justify="right", no_wrap=True)
        for finding in report.findings:
            style = {
                Severity.CRITICAL: "bold red",
                Severity.HIGH: "bold bright_red",
                Severity.MEDIUM: "bold yellow",
                Severity.LOW: "bold blue",
                Severity.INFO: "bold green",
            }[finding.severity]
            table.add_row(
                Text(finding.severity.value.upper(), style=style),
                Text(sanitize_text(finding.subject_name)),
                Text(
                    f"{finding.rule_id} · {sanitize_text(finding.title)}\n"
                    f"{sanitize_text(finding.message)}"
                ),
                f"{finding.confidence:.0%}",
            )
        console.print(table)
    else:
        console.print("[green]✓[/green] No reportable findings.")

    if report.notices:
        notes = "\n".join(f"• {sanitize_text(note)}" for note in report.notices)
        console.print(Panel(notes, title="Notes"))


def html_report(report: ScanReport) -> str:
    """Render a self-contained, autoescaped visual report from scanner-owned data."""
    environment = Environment(
        loader=PackageLoader("mcpsentinel", "templates"),
        autoescape=select_autoescape(["html", "htm", "xml"]),
    )
    template = environment.get_template("risk_report.html")
    return template.render(
        report=safe_report_payload(report),
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
