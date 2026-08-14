"""Command-line interface for MCPSentinel."""

from __future__ import annotations

import argparse
import asyncio
import json
import shlex
import sys
from pathlib import Path
from urllib.parse import urlparse

from .discovery import DiscoveryError
from .dynamic import DynamicConfig, DynamicInvocation, DynamicValidationError
from .models import Severity, TargetConfig
from .reporting import write_report
from .service import reaches_fail_threshold, scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpsentinel",
        description="Precision-first security scanning for Model Context Protocol servers.",
    )
    commands = parser.add_subparsers(dest="command_name", required=True)
    scan_parser = commands.add_parser("scan", help="Discover and scan MCP server metadata.")
    scan_parser.add_argument("target", help="HTTP MCP URL or a quoted stdio command.")
    scan_parser.add_argument("--transport", choices=("auto", "http", "stdio"), default="auto")
    scan_parser.add_argument(
        "--command", help="Stdio executable; overrides command parsed from target."
    )
    scan_parser.add_argument(
        "--arg",
        action="append",
        default=[],
        help="Argument for --command; use --arg=-m for values beginning with '-'. Repeatable.",
    )
    scan_parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Environment override for stdio.",
    )
    scan_parser.add_argument(
        "--rules", type=Path, help="JSON file with additive custom static rules."
    )
    scan_parser.add_argument("--policy", type=Path, help="JSON allow/deny policy file.")
    scan_parser.add_argument(
        "--baseline-dir",
        type=Path,
        default=Path("~/.mcpsentinel"),
        help="Directory used for metadata snapshots and judge cache (default: ~/.mcpsentinel).",
    )
    scan_parser.add_argument(
        "--no-baseline-update", action="store_true", help="Read but do not update baseline."
    )
    scan_parser.add_argument(
        "--judge",
        choices=("auto", "heuristic", "openai"),
        default="heuristic",
        help="Semantic judge; heuristic is offline by default, while openai transmits metadata.",
    )
    scan_parser.add_argument("--judge-model", default="gpt-4o-mini")
    scan_parser.add_argument("--semantic-threshold", type=_confidence, default=0.70)
    scan_parser.add_argument("--format", choices=("text", "json", "sarif", "html"), default="text")
    scan_parser.add_argument(
        "--output", type=Path, help="Write report to this path as well as stdout."
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=("none", *(severity.value for severity in Severity)),
        default="none",
        help="Return exit code 1 when a finding reaches this severity.",
    )
    dynamic_group = scan_parser.add_argument_group("dynamic Docker validation (opt-in)")
    dynamic_group.add_argument(
        "--dynamic", action="store_true", help="Enable Docker-sandbox tool calls."
    )
    dynamic_group.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="Required acknowledgement for dynamic execution against an owned/local server.",
    )
    dynamic_group.add_argument(
        "--dynamic-image", help="Pre-built, local Docker image containing the MCP server."
    )
    dynamic_group.add_argument(
        "--dynamic-entrypoint",
        help="Optional quoted command to run as the image entrypoint; no shell is used.",
    )
    dynamic_group.add_argument(
        "--dynamic-invoke",
        action="append",
        default=[],
        metavar="TOOL=JSON",
        help="Explicit owned-tool invocation and JSON object input. Repeatable.",
    )
    dynamic_group.add_argument("--dynamic-timeout", type=_positive_seconds, default=10)
    dynamic_group.add_argument("--dynamic-confidence", type=_confidence, default=0.80)
    return parser


def _confidence(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("confidence must be a number from 0 to 1") from error
    if not 0 <= value <= 1:
        raise argparse.ArgumentTypeError("confidence must be a number from 0 to 1")
    return value


def _positive_seconds(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be a whole number of seconds") from error
    if not 1 <= value <= 60:
        raise argparse.ArgumentTypeError("timeout must be from 1 to 60 seconds")
    return value


def _target_from_args(args: argparse.Namespace) -> TargetConfig:
    parsed = urlparse(args.target)
    transport = args.transport
    if transport == "auto":
        transport = "http" if parsed.scheme in {"http", "https"} else "stdio"
    if transport == "http":
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("HTTP targets must begin with http:// or https://.")
        return TargetConfig(transport="http", identity=args.target, url=args.target)

    if args.command:
        command = args.command
        command_args = tuple(args.arg)
    else:
        pieces = shlex.split(args.target)
        if not pieces:
            raise ValueError("A stdio target must contain an executable command.")
        command, *command_args = pieces
        command_args = [*command_args, *args.arg]
    environment: dict[str, str] = {}
    for item in args.env:
        key, separator, value = item.partition("=")
        if not separator or not key:
            raise ValueError("Each --env value must use KEY=VALUE.")
        environment[key] = value
    identity = " ".join([command, *command_args])
    return TargetConfig(
        transport="stdio",
        identity=identity,
        command=command,
        arguments=tuple(command_args),
        environment=environment,
    )


async def _run(args: argparse.Namespace) -> int:
    target = _target_from_args(args)
    report = await scan(
        target,
        rules_path=args.rules,
        policy_path=args.policy,
        baseline_root=args.baseline_dir,
        update_baseline=not args.no_baseline_update,
        judge_kind=args.judge,
        judge_model=args.judge_model,
        semantic_threshold=args.semantic_threshold,
        dynamic_config=_dynamic_from_args(args),
    )
    rendered = write_report(report, args.format, args.output)
    print(rendered, end="")
    threshold = None if args.fail_on == "none" else Severity(args.fail_on)
    return 1 if reaches_fail_threshold(report, threshold) else 0


def _dynamic_from_args(args: argparse.Namespace) -> DynamicConfig | None:
    if not args.dynamic:
        return None
    if not args.i_own_this_target:
        raise DynamicValidationError("--dynamic requires --i-own-this-target.")
    if not args.dynamic_image:
        raise DynamicValidationError("--dynamic requires --dynamic-image.")
    invocations: list[DynamicInvocation] = []
    for raw in args.dynamic_invoke:
        tool_name, separator, raw_json = raw.partition("=")
        if not separator or not tool_name:
            raise DynamicValidationError("Each --dynamic-invoke must use TOOL=JSON.")
        if len(raw_json) > 16384:
            raise DynamicValidationError("Dynamic JSON input must not exceed 16 KiB.")
        try:
            tool_args = json.loads(raw_json)
        except json.JSONDecodeError as error:
            raise DynamicValidationError(
                f"Dynamic input for {tool_name!r} is not valid JSON: {error.msg}"
            ) from error
        if not isinstance(tool_args, dict):
            raise DynamicValidationError("Dynamic tool input must be a JSON object.")
        invocations.append(DynamicInvocation(tool_name=tool_name, arguments=tool_args))
    entrypoint = tuple(shlex.split(args.dynamic_entrypoint)) if args.dynamic_entrypoint else ()
    return DynamicConfig(
        image=args.dynamic_image,
        invocations=tuple(invocations),
        entrypoint=entrypoint,
        timeout_seconds=args.dynamic_timeout,
        confidence_threshold=args.dynamic_confidence,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except (DiscoveryError, DynamicValidationError, ValueError, RuntimeError) as error:
        print(f"mcpsentinel: error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
