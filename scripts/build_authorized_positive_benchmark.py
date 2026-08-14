#!/usr/bin/env python3
"""Build Benchmark v3 from Cisco's source-labelled, malicious MCP fixtures.

This extractor reads only a local checkout at a pinned Git revision. It does
not execute a fixture, start an MCP server, or contact an endpoint. The two
included source families have explicit first-party labels in their directory
names and each extracted FastMCP tool publishes its full docstring as metadata.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

REPOSITORY = "https://github.com/cisco-ai-defense/mcp-scanner"
PROVENANCE = "source-attributed-authorized-positive-control"
FAMILIES = (
    ("prompt-injection", "MCP001"),
    ("unauthorized-code-execution", "MCP004"),
)
EXCLUDED_FILES = {
    "evals/behavioral-analysis/data/unauthorized-code-execution/dynamic_import_arbitrary_module.py",
    "evals/behavioral-analysis/data/unauthorized-code-execution/unrestricted_exec_arbitrary_code.py",
    "evals/behavioral-analysis/data/unauthorized-code-execution/unsafe_pickle_deserialization.py",
    "evals/behavioral-analysis/data/unauthorized-code-execution/yaml_unsafe_load_code_execution.py",
}
EXTRA_RULES_BY_PATH = {
    "evals/behavioral-analysis/data/prompt-injection/act_as_role_injection.py": (
        "MCP004",
    ),
    "evals/behavioral-analysis/data/prompt-injection/hidden_system_instructions.py": (
        "MCP004",
    ),
}


@dataclass(frozen=True)
class ExtractedTool:
    """One metadata-visible FastMCP fixture with a source-authored class label."""

    family: str
    rule_ids: tuple[str, ...]
    name: str
    description: str
    path: str
    line: int
    source_sha256: str


def _checkout_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    commit = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError(f"{root} did not resolve to a full Git commit SHA.")
    return commit


def _is_tool_decorator(value: ast.expr) -> bool:
    target = value.func if isinstance(value, ast.Call) else value
    return (
        isinstance(target, ast.Attribute)
        and target.attr == "tool"
        and isinstance(target.value, ast.Name)
        and target.value.id == "app"
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_tools(root: Path) -> list[ExtractedTool]:
    """Extract all fully documented ``@app.tool`` fixtures in the selected families."""
    base = root / "evals" / "behavioral-analysis" / "data"
    records: list[ExtractedTool] = []
    for family, rule_id in FAMILIES:
        for path in sorted((base / family).glob("*.py")):
            relative_path = path.relative_to(root).as_posix()
            if relative_path in EXCLUDED_FILES:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            tool_nodes = [
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and any(_is_tool_decorator(decorator) for decorator in node.decorator_list)
            ]
            if len(tool_nodes) != 1:
                raise ValueError(
                    f"Expected exactly one @app.tool fixture in {path.relative_to(root)}."
                )
            node = tool_nodes[0]
            description = ast.get_docstring(node, clean=True)
            if not description:
                raise ValueError(f"Fixture {path.relative_to(root)} has no tool docstring.")
            records.append(
                ExtractedTool(
                    family=family,
                    rule_ids=(rule_id, *EXTRA_RULES_BY_PATH.get(relative_path, ())),
                    name=node.name,
                    description=description,
                    path=relative_path,
                    line=node.lineno,
                    source_sha256=_sha256(path),
                )
            )
    return records


def build_manifest(root: Path) -> dict[str, object]:
    """Return the deterministic, literal source-attributed v3 manifest."""
    tools = extract_tools(root)
    if len(tools) != 16:
        raise ValueError(f"Expected 16 selected fixtures, extracted {len(tools)}.")
    return {
        "version": 3,
        "name": "authorized-positive-metadata-v3",
        "purpose": (
            "Source-attributed positive control for metadata-visible prompt injection and "
            "unbounded code-execution fixtures. It measures rule behavior only against "
            "these first-party, intentionally malicious lab descriptions."
        ),
        "evaluation_scope": "authorized-metadata-positive-control",
        "labeling": {
            "rubric": (
                "Cisco classifies every selected fixture in its source directory as either "
                "prompt-injection or unauthorized-code-execution. MCPSentinel maps those "
                "source-authored classes to MCP001 and MCP004 respectively; two prompt-"
                "injection descriptions also explicitly advertise unrestricted command "
                "execution and carry MCP004. The complete FastMCP function docstring is "
                "the declared metadata under test."
            ),
            "review_status": "maintainer-reviewed; independent-review-pending",
            "reviewer_count": 1,
        },
        "sources": [
            {
                "id": "cisco",
                "repository": REPOSITORY,
                "commit": _checkout_commit(root),
                "license": "Apache-2.0",
                "license_path": "LICENSE",
                "authorization": (
                    "Apache-2.0 licensed test/evaluation fixtures published by Cisco; selected "
                    "directories carry Cisco-authored malicious scenario labels."
                ),
                "extraction": (
                    "Full docstring of the one @app.tool function in each selected "
                    "behavioral-analysis fixture."
                ),
                "case_count": len(tools),
            }
        ],
        "cases": [
            {
                "id": f"cisco-{tool.family}-{index:03d}",
                "name": tool.name,
                "description": tool.description,
                "expected_rules": list(tool.rule_ids),
                "expected_reported_rules": list(tool.rule_ids),
                "provenance": PROVENANCE,
                "source": {
                    "source_id": "cisco",
                    "source_label": tool.family,
                    "path": tool.path,
                    "line": tool.line,
                    "sha256": tool.source_sha256,
                },
            }
            for index, tool in enumerate(tools, start=1)
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_manifest(args.source_root.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
