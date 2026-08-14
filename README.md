# MCPSentinel

<!-- mcp-name: io.github.gentaArnezzi/mcpsentinel -->

MCPSentinel is a precision-first security scanner for [Model Context Protocol](https://modelcontextprotocol.io/) servers. It treats a static rule hit as a candidate, then applies semantic intent analysis before reporting it. This keeps the fast coverage of pattern matching without making every normal-looking `fetch` or `delete` tool a noisy vulnerability.

MCPSentinel now implements the PRD feature set:

- MCP discovery over stdio and Streamable HTTP
- configurable static pattern rules for tool, prompt, and resource descriptors, including tool poisoning, shadowing, cross-server, and OAuth confused-deputy signals
- semantic triage: offline heuristic by default, optional OpenAI structured-output judge
- baseline snapshots and rug-pull definition diffs
- terminal, JSON, SARIF, and self-contained HTML risk reports
- allow/deny policy configuration
- explicit, Docker-sandboxed owned-tool validation with no network egress
- GitHub Action and MCP-native scanner interfaces

Static scans are metadata-only. Dynamic invocation is a separate opt-in path described below and never runs from the GitHub Action or MCP-native server.

## Install

Install the published package, then use the MCPSentinel CLI:

```bash
python -m pip install mcp-guardian-scan
mcpsentinel
```

Running `mcpsentinel` with no command starts a short, no-write terminal
onboarding guide. It explains the read-only scan model, gives a copy-pasteable
first scan, and keeps OpenAI optional. Use `mcpsentinel onboard` (or the alias
`mcpsentinel init`) to show it again, or tailor the suggested command without
contacting a server:

```bash
mcpsentinel onboard --target https://mcp.example.com/mcp
mcpsentinel onboard --target "python -m example_mcp_server" --transport stdio
```

The onboarding flow never asks for, stores, or transmits an API key. Use
`mcpsentinel --help` or `mcpsentinel scan --help` for the complete reference.

For development from source:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Scan a server

For a Streamable HTTP server:

```bash
mcpsentinel scan http://localhost:8000/mcp
```

For a stdio server, quote its command as the target:

```bash
mcpsentinel scan "python -m example_mcp_server" --transport stdio
```

Or keep the executable and arguments separate. Arguments beginning with a dash need the `--arg=value` form:

```bash
mcpsentinel scan python --transport stdio --arg=-m --arg=example_mcp_server
```

Useful options:

```bash
# Machine-readable report and CI failure gate
mcpsentinel scan http://localhost:8000/mcp --format sarif --output results.sarif --fail-on high

# Visual portfolio-ready report
mcpsentinel scan http://localhost:8000/mcp --format html --output risk-report.html

# Use OpenAI's structured-output semantic judge (OPENAI_API_KEY is required)
mcpsentinel scan http://localhost:8000/mcp --judge openai --judge-model gpt-4o-mini

# Keep the generated baseline out of the user cache, useful in CI
mcpsentinel scan http://localhost:8000/mcp --baseline-dir .mcpsentinel/baselines
```

Baseline snapshots are kept in `~/.mcpsentinel/baselines` by default. A changed, added, or removed descriptor is surfaced as an `MCP-B001` rug-pull review finding, then the snapshot is updated. Use `--no-baseline-update` for a read-only CI run.

The risk score is a capped 0–100 weighted sum of severity and semantic confidence. It is a prioritization signal, not a claim that the server is safe or unsafe in isolation.

## Semantic judges

`--judge heuristic` is the default and is fully offline. `--judge openai` requires `OPENAI_API_KEY`; `--judge auto` opts into using OpenAI when that key is present, otherwise it uses the heuristic. The OpenAI judge uses the Python SDK's Responses structured-output API, so an API response cannot bypass the scanner's expected verdict schema. Results are cached by descriptor hash and judge identity in the baseline directory to avoid repeat API charges.

Each OpenAI judgement uses a 30-second client deadline and at most two SDK retries. The default heuristic remains the recommended choice when external model latency or metadata transmission is not acceptable.

The semantic threshold defaults to `0.70`. Candidate findings below it are withheld from the report; lower it only when you prefer recall over precision.

## Custom static rules

Pass `--rules path/to/rules.json` to add rule objects to the built-in rules. Each rule has this shape:

```json
{
  "id": "ORG001",
  "title": "Example organization policy",
  "category": "tool_poisoning",
  "severity": "high",
  "description": "Why this candidate deserves semantic review.",
  "patterns": ["(?i)example pattern"],
  "fields": ["description", "schema"]
}
```

Supported categories are `prompt_injection`, `tool_poisoning`, `tool_shadowing`, `ssrf`, `secret_exfiltration`, `command_execution`, `destructive_operation`, `cross_server_attack`, `oauth_confused_deputy`, and `rug_pull`.

## Policy configuration

`--policy path/to/policy.json` supplies organization-specific allow/deny controls. An allow selector suppresses matching static candidates; a deny selector emits a policy-enforced finding without relying on the semantic judge. Selectors can be rule IDs or objects scoped to a tool-name regex.

```json
{
  "allow": [{"rule_id": "MCP003", "subject_pattern": "^controlled_fetch$"}],
  "deny": ["MCP002"],
  "semantic_threshold": 0.75
}
```

See [examples/policy.json](examples/policy.json) for a complete file. Keep policy files under source control and review changes as security-sensitive configuration.

## Dynamic Docker validation

Dynamic testing is intentionally opt-in and limited to a server you own or a local test fixture. It requires an explicit acknowledgement, a pre-built local image, an explicit high-confidence tool name, and JSON arguments. The runner creates a fresh Docker container with no network, no host mounts, a read-only root filesystem, dropped capabilities, an unprivileged user, resource limits, and a call timeout. It never forwards the scan process environment into the container.

```bash
mcpsentinel scan "python -m my_server" --transport stdio \
  --dynamic --i-own-this-target \
  --dynamic-image my-mcp-server:test \
  --dynamic-entrypoint "python -m my_server" \
  --dynamic-invoke 'unsafe_tool={"fixture": true}'
```

The dynamic server image must already exist locally; MCPSentinel uses `--pull=never`. Docker is not needed for normal metadata scans. A dynamic response is retained only as a SHA-256 digest and content-type summary. If it resembles credential material, MCPSentinel reports `MCP-D001` without writing the response text to disk.

The repository includes a deliberately local-only Docker fixture to verify this boundary end to end. It is excluded from the normal test suite because it needs a running Docker daemon and builds an image:

```bash
MCPSENTINEL_RUN_DOCKER_TESTS=1 pytest tests/test_dynamic_docker_e2e.py
```

## GitHub Action

The repository root is a composite GitHub Action. It installs MCPSentinel, restores a scoped baseline cache, emits SARIF, and fails at the selected severity. It does not enable dynamic testing.

```yaml
- uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
- uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
  with:
    python-version: "3.12"
- uses: ./
  id: mcpsentinel
  with:
    target: https://mcp.example.com/mcp
    transport: http
    fail-on: high
    policy: .mcpsentinel/policy.json
- uses: github/codeql-action/upload-sarif@d6317709a54fd87078d323eeb0e48ec331c8e621 # v3
  with:
    sarif_file: ${{ steps.mcpsentinel.outputs.sarif }}
```

Set `OPENAI_API_KEY` in the workflow only when choosing `judge: openai`; `heuristic` remains the default.

## MCP-native scanner

Run `mcpsentinel-mcp` to expose the scanner as the MCP tool `scan_mcp_server` over stdio. It is intentionally more constrained than the CLI: dynamic execution is unavailable, target configuration is operator-controlled, HTTP targets must be explicitly allowlisted, and stdio targets are disabled unless the operator enables them.

```bash
export MCPSENTINEL_ALLOWED_HOSTS="mcp.example.com,localhost"
mcpsentinel-mcp
```

The allowlist accepts either `host` or an exact `host:port`. HTTP redirects are refused, each discovery session has a 30-second deadline, and resolved private or reserved addresses are denied by default. For a deliberately trusted local network, set `MCPSENTINEL_ALLOW_PRIVATE_HTTP_TARGETS=true` alongside its exact allowlist entry.

Optional operator settings are `MCPSENTINEL_MCP_BASELINE_DIR`, `MCPSENTINEL_RULES_PATH`, `MCPSENTINEL_POLICY_PATH`, `MCPSENTINEL_MCP_JUDGE`, and `MCPSENTINEL_MCP_JUDGE_MODEL`. Set `MCPSENTINEL_ALLOW_STDIO_TARGETS=true` only in a trusted local environment. The MCP caller cannot choose arbitrary policy files or baseline paths.

## Registry publication readiness

The concrete [registry/server.json](registry/server.json) is prepared for PyPI plus the official MCP Registry. Before publishing a release, build and upload the matching package version to PyPI, then authenticate and submit that same `server.json` with `mcp-publisher`. The required hidden `mcp-name` marker is already in this README. The registry validates PyPI ownership through that marker and requires a namespace matching the account used to authenticate; it does not host package artifacts itself. See [registry/README.md](registry/README.md) for owner-specific commands and the official [package-type documentation](https://modelcontextprotocol.io/registry/package-types).

## Container image

Build the scanner image for normal metadata scans:

```bash
docker build -t mcpsentinel:local .
docker run --rm mcpsentinel:local scan https://mcp.example.com/mcp --transport http
```

The image intentionally has no Docker socket and cannot run the dynamic layer. Run dynamic validation from a trusted host with Docker configured.

## Dataset

[datasets/vulnerable_by_design](datasets/vulnerable_by_design) holds controlled descriptor-level ground truth for regression tests across every default static rule plus a bounded safe control. It contains no live third-party targets or runnable destructive payloads.

Run a reproducible accuracy and timing measurement with the offline judge:

```bash
mcpsentinel benchmark datasets/vulnerable_by_design/manifest.json --format json --output benchmark.json
```

The benchmark measures both raw static candidates and semantic findings against the dataset's expected reportable rules. It reports precision, recall, false-positive rate, F1, confusion-matrix counts, and stage timings. The bounded-fetch control intentionally counts as a static false positive but a semantic true negative, so regressions in noise suppression are visible in CI or release review. This is controlled regression evidence, not a general claim about production-server accuracy.

## Development

```bash
pytest
ruff check .
```

The project is intentionally dependency-light: `mcp` handles protocol discovery, while the core rule engine, snapshot store, and report writers use the standard library.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and supported-version information.
