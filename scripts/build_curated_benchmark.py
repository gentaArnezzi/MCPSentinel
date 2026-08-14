#!/usr/bin/env python3
"""Build the source-attributed public-metadata Benchmark v2 manifest.

This utility deliberately consumes local, pinned checkouts. It never connects
to, invokes, or scans a third-party MCP endpoint. The resulting manifest keeps
only each tool name, the first paragraph of its declared documentation, and a
source-file SHA-256 so reviewers can reproduce the extraction from the commit
recorded in the manifest.
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

AWS_REPOSITORY = "https://github.com/awslabs/mcp"
GITHUB_REPOSITORY = "https://github.com/github/github-mcp-server"
PROVENANCE = "source-attributed-public-metadata"


@dataclass(frozen=True)
class ExtractedTool:
    """A descriptor extracted from one locally checked-out upstream source file."""

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


def _first_paragraph(value: str) -> str:
    return re.split(r"\n\s*\n", value.strip(), maxsplit=1)[0].replace("\n", " ").strip()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_python_tool_decorator(value: ast.expr) -> bool:
    target = value.func if isinstance(value, ast.Call) else value
    return (
        isinstance(target, ast.Attribute)
        and target.attr == "tool"
        and isinstance(target.value, ast.Name)
        and target.value.id in {"mcp", "server"}
    )


def extract_aws_tools(root: Path) -> list[ExtractedTool]:
    """Extract FastMCP-decorated functions and their first docstring paragraph."""
    records: list[ExtractedTool] = []
    source_root = root / "src"
    for path in sorted(source_root.rglob("*.py")):
        if {"test", "tests", "evals"} & set(path.parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        source_sha256 = _sha256(path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            tool_decorators = [
                decorator
                for decorator in node.decorator_list
                if _is_python_tool_decorator(decorator)
            ]
            if not tool_decorators:
                continue
            name = node.name
            for decorator in tool_decorators:
                if not isinstance(decorator, ast.Call):
                    continue
                for keyword in decorator.keywords:
                    if (
                        keyword.arg == "name"
                        and isinstance(keyword.value, ast.Constant)
                        and isinstance(keyword.value.value, str)
                    ):
                        name = keyword.value.value
            docstring = ast.get_docstring(node, clean=True)
            if not docstring:
                continue
            description = _first_paragraph(docstring)
            if description:
                records.append(
                    ExtractedTool(
                        name=name,
                        description=description,
                        path=path.relative_to(root).as_posix(),
                        line=node.lineno,
                        source_sha256=source_sha256,
                    )
                )
    return records


_NAME = re.compile(r'\bName\s*:\s*"((?:\\.|[^"\\])*)"')
_DESCRIPTION = re.compile(
    r'\bDescription\s*:\s*t\(\s*"(?:\\.|[^"\\])*"\s*,\s*"((?:\\.|[^"\\])*)"',
    re.DOTALL,
)


def _go_composite_literals(source: str) -> list[tuple[int, str]]:
    """Return balanced ``mcp.Tool{...}`` literals while respecting Go strings."""
    records: list[tuple[int, str]] = []
    cursor = 0
    while True:
        start = source.find("mcp.Tool{", cursor)
        if start < 0:
            return records
        depth = 0
        quote: str | None = None
        escape = False
        end = start
        while end < len(source):
            character = source[end]
            if quote:
                if quote == "`":
                    if character == "`":
                        quote = None
                elif escape:
                    escape = False
                elif character == "\\":
                    escape = True
                elif character == quote:
                    quote = None
            elif character in {'"', "`"}:
                quote = character
            elif character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    end += 1
                    break
            end += 1
        records.append((start, source[start:end]))
        cursor = end


def extract_github_tools(root: Path) -> list[ExtractedTool]:
    """Extract literal Go ``mcp.Tool`` names and default English descriptions."""
    records: list[ExtractedTool] = []
    source_root = root / "pkg" / "github"
    for path in sorted(source_root.glob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        source = path.read_text(encoding="utf-8")
        source_sha256 = _sha256(path)
        for offset, literal in _go_composite_literals(source):
            name = _NAME.search(literal)
            description = _DESCRIPTION.search(literal)
            if not name or not description:
                continue
            records.append(
                ExtractedTool(
                    name=bytes(name.group(1), "utf-8").decode("unicode_escape"),
                    description=_first_paragraph(
                        bytes(description.group(1), "utf-8").decode("unicode_escape")
                    ),
                    path=path.relative_to(root).as_posix(),
                    line=source[:offset].count("\n") + 1,
                    source_sha256=source_sha256,
                )
            )
    return records


def _case(source_id: str, index: int, tool: ExtractedTool) -> dict[str, object]:
    return {
        "id": f"{source_id}-{index:03d}",
        "name": tool.name,
        "description": tool.description,
        "expected_rules": [],
        "expected_reported_rules": [],
        "provenance": PROVENANCE,
        "source": {
            "source_id": source_id,
            "path": tool.path,
            "line": tool.line,
            "sha256": tool.source_sha256,
        },
    }


def build_manifest(aws_root: Path, github_root: Path) -> dict[str, object]:
    aws_tools = extract_aws_tools(aws_root)
    github_tools = extract_github_tools(github_root)
    if len({(tool.path, tool.line) for tool in aws_tools}) != len(aws_tools):
        raise ValueError("AWS extraction produced duplicate source locations.")
    if len({tool.name for tool in github_tools}) != len(github_tools):
        raise ValueError("GitHub extraction produced duplicate tool names.")
    return {
        "version": 2,
        "name": "curated-public-metadata-v2",
        "purpose": (
            "Source-attributed public MCP tool metadata negative control. It measures whether "
            "MCPSentinel invents unbounded-risk findings from ordinary documented tools; it does "
            "not label a source project or tool as vulnerable."
        ),
        "evaluation_scope": "public-metadata-negative-control",
        "labeling": {
            "rubric": (
                "A case is labelled with a rule only when its exposed metadata itself advertises "
                "that rule's unbounded-risk condition. The selected documented tools do not do so, "
                "therefore every expected rule set is empty."
            ),
            "review_status": "maintainer-reviewed; independent-review-pending",
            "reviewer_count": 1,
        },
        "sources": [
            {
                "id": "aws",
                "repository": AWS_REPOSITORY,
                "commit": _checkout_commit(aws_root),
                "license": "Apache-2.0",
                "license_path": "LICENSE",
                "extraction": "FastMCP-decorated function name plus first docstring paragraph",
                "case_count": len(aws_tools),
            },
            {
                "id": "github",
                "repository": GITHUB_REPOSITORY,
                "commit": _checkout_commit(github_root),
                "license": "MIT",
                "license_path": "LICENSE",
                "extraction": "literal mcp.Tool name plus default English Description argument",
                "case_count": len(github_tools),
            },
        ],
        "cases": [
            *[_case("aws", index, tool) for index, tool in enumerate(aws_tools, start=1)],
            *[
                _case("github", index, tool)
                for index, tool in enumerate(github_tools, start=1)
            ],
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aws-root", type=Path, required=True)
    parser.add_argument("--github-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_manifest(args.aws_root.resolve(), args.github_root.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
