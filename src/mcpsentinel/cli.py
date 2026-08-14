"""Command-line interface for MCPSentinel."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import sys
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from . import __version__
from .benchmark import BenchmarkConfigurationError, benchmark_json, benchmark_text, run_benchmark
from .discovery import DiscoveryError
from .dynamic import DynamicConfig, DynamicInvocation, DynamicValidationError
from .models import Severity, TargetConfig
from .reporting import terminal_report, write_report
from .semantic import build_judge
from .service import reaches_fail_threshold, scan

_ONBOARDING_BANNER = """+----------------------------------------------------------------+
|                          MCPSENTINEL                           |
|       Security review for Model Context Protocol servers        |
|                     Read-only by default                       |
+----------------------------------------------------------------+
"""

_STDIO_EXECUTION_WARNING = (
    "MCPSentinel must start this MCP server process to inspect its metadata.\n\n"
    "The process is NOT sandboxed and may access filesystem and network resources "
    "available to your operating-system user. Environment credentials are withheld by "
    "default, but host execution is still a trust boundary.\n\n"
    "Only scan stdio executables you trust to start locally."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpsentinel",
        description="Precision-first security scanning for Model Context Protocol servers.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command_name")
    onboarding_parser = commands.add_parser(
        "onboard",
        aliases=("init",),
        help="Show a safe, guided first-scan walkthrough without writing files or reading secrets.",
    )
    onboarding_parser.add_argument(
        "--target",
        help="Optional target used only to print a scan command; no server is contacted.",
    )
    onboarding_parser.add_argument(
        "--transport",
        choices=("auto", "http", "stdio"),
        default="auto",
        help="Transport for the optional target (default: auto).",
    )
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
        help="Explicit environment value for the stdio child; values are redacted from reports.",
    )
    scan_parser.add_argument(
        "--inherit-env",
        action="store_true",
        help=(
            "UNSAFE: forward the full scanner environment to the stdio child. "
            "Disabled by default because it can expose credentials."
        ),
    )
    scan_parser.add_argument(
        "--rules", type=Path, help="JSON file with additive custom static rules."
    )
    scan_parser.add_argument("--policy", type=Path, help="JSON allow/deny policy file.")
    scan_parser.add_argument(
        "--baseline-dir",
        type=Path,
        default=Path("~/.mcpsentinel"),
        help="Approved metadata snapshots and judge cache (default: ~/.mcpsentinel).",
    )
    scan_parser.add_argument(
        "--approve-baseline",
        action="store_true",
        help="Explicitly replace the approved metadata baseline after reviewing this scan.",
    )
    scan_parser.add_argument(
        "--no-baseline-update",
        action="store_true",
        help="Compatibility option; scans preserve the baseline unless --approve-baseline is set.",
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

    benchmark_parser = commands.add_parser(
        "benchmark", help="Measure labelled scanner behavior against a benchmark dataset."
    )
    benchmark_parser.add_argument(
        "dataset",
        type=Path,
        nargs="?",
        default=Path("datasets/vulnerable_by_design/manifest.json"),
        help="Labelled JSON dataset (default: datasets/vulnerable_by_design/manifest.json).",
    )
    benchmark_parser.add_argument(
        "--rules", type=Path, help="JSON file with additive custom static rules."
    )
    benchmark_parser.add_argument(
        "--judge",
        choices=("auto", "heuristic", "openai"),
        default="heuristic",
        help="Semantic judge; heuristic is offline by default, while openai transmits metadata.",
    )
    benchmark_parser.add_argument("--judge-model", default="gpt-4o-mini")
    benchmark_parser.add_argument("--semantic-threshold", type=_confidence, default=0.70)
    benchmark_parser.add_argument("--format", choices=("text", "json"), default="text")
    benchmark_parser.add_argument(
        "--output", type=Path, help="Write the benchmark report to this path."
    )
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


def _onboarding_text(target: str | None = None, transport: str = "auto") -> str:
    """Return a copy-pasteable, no-write first-run guide for terminal users."""
    if target:
        chosen_transport = transport
        if chosen_transport == "auto":
            chosen_transport = "http" if urlparse(target).scheme in {"http", "https"} else "stdio"
        first_scan = f"mcpsentinel scan {shlex.quote(target)} --transport {chosen_transport}"
    else:
        first_scan = "mcpsentinel scan http://localhost:8000/mcp"

    openai_hint = (
        "OPENAI_API_KEY is detected; use --judge auto only when metadata may be sent to OpenAI."
        if os.environ.get("OPENAI_API_KEY")
        else "No OpenAI key is needed for this first scan; the default heuristic judge is offline."
    )
    return f"""{_ONBOARDING_BANNER}
Welcome to MCPSentinel {__version__}

MCPSentinel discovers MCP metadata, applies static security rules, and then
triages candidate findings. A normal scan is read-only: it does not invoke
server tools. Dynamic tool validation is a separate explicit opt-in.

1. Run your first offline scan:
   {first_scan}

2. Save CI-friendly output and fail on high-severity findings:
   {first_scan} --format sarif --output results.sarif --fail-on high

3. Review the baseline diff on later scans. Baselines default to:
   ~/.mcpsentinel/baselines
   After review, create or replace one explicitly:
   {first_scan} --approve-baseline

4. Optional semantic review:
   {openai_hint}
   export OPENAI_API_KEY="..."
   {first_scan} --judge openai --judge-model gpt-4o-mini

Useful next commands:
   mcpsentinel scan --help       # every scan option
   mcpsentinel benchmark         # validate rules against the bundled dataset
   mcpsentinel onboard --target "python -m my_mcp_server" --transport stdio

Security note: never commit API keys. Keep --dynamic disabled unless you own
the target and intentionally provide its local Docker image.
"""


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
        inherit_environment=args.inherit_env,
    )


async def _run_scan(args: argparse.Namespace) -> int:
    if args.approve_baseline and args.no_baseline_update:
        raise ValueError("--approve-baseline cannot be combined with --no-baseline-update.")
    target = _target_from_args(args)
    if target.transport == "stdio" and args.format == "text" and sys.stdout.isatty():
        Console().print(
            Panel(
                Text(_STDIO_EXECUTION_WARNING),
                title="[bold yellow]⚠ Stdio target execution[/bold yellow]",
                border_style="yellow",
            )
        )
    report = await scan(
        target,
        rules_path=args.rules,
        policy_path=args.policy,
        baseline_root=args.baseline_dir,
        update_baseline=args.approve_baseline,
        judge_kind=args.judge,
        judge_model=args.judge_model,
        semantic_threshold=args.semantic_threshold,
        dynamic_config=_dynamic_from_args(args),
    )
    if args.format == "text" and sys.stdout.isatty():
        if args.output is not None:
            write_report(report, args.format, args.output)
        terminal_report(report)
    else:
        rendered = write_report(report, args.format, args.output)
        print(rendered, end="")
    threshold = None if args.fail_on == "none" else Severity(args.fail_on)
    return 1 if reaches_fail_threshold(report, threshold) else 0


async def _run_benchmark(args: argparse.Namespace) -> int:
    report = await run_benchmark(
        dataset_path=args.dataset,
        judge=build_judge(args.judge, args.judge_model),
        semantic_threshold=args.semantic_threshold,
        rules_path=args.rules,
    )
    rendered = benchmark_json(report) if args.format == "json" else benchmark_text(report)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


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
    if args.command_name is None:
        print(_onboarding_text(), end="")
        return 0
    if args.command_name in {"onboard", "init"}:
        print(_onboarding_text(args.target, args.transport), end="")
        return 0
    try:
        runner = _run_scan if args.command_name == "scan" else _run_benchmark
        return asyncio.run(runner(args))
    except (
        BenchmarkConfigurationError,
        DiscoveryError,
        DynamicValidationError,
        ValueError,
        RuntimeError,
    ) as error:
        print(f"mcpsentinel: error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
