<!-- mcp-name: io.github.gentaArnezzi/mcpsentinel -->

# MCPSentinel

<div align="center">

<pre>
+----------------------------------------------------------------+
|                          MCPSENTINEL                           |
|       Security review for Model Context Protocol servers        |
|                     Read-only by default                       |
+----------------------------------------------------------------+
</pre>

<p><strong>Discover MCP metadata. Triage suspicious intent. Review changes before you trust them.</strong></p>

[![CI](https://github.com/gentaArnezzi/MCPSentinel/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gentaArnezzi/MCPSentinel/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-guardian-scan?label=PyPI)](https://pypi.org/project/mcp-guardian-scan/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-guardian-scan)](https://pypi.org/project/mcp-guardian-scan/)
[![License](https://img.shields.io/github/license/gentaArnezzi/MCPSentinel)](LICENSE)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-listed-6A5ACD)](https://registry.modelcontextprotocol.io/)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-ready-2088FF?logo=githubactions)](https://github.com/gentaArnezzi/MCPSentinel)

</div>

MCPSentinel is a precision-first security scanner for [Model Context Protocol](https://modelcontextprotocol.io/) servers. It treats a static rule hit as a candidate, then applies semantic intent analysis before reporting it. This keeps the fast coverage of pattern matching without making every normal-looking `fetch` or `delete` tool a noisy vulnerability.

## Start in 60 seconds

```bash
python -m pip install mcp-guardian-scan
mcpsentinel                    # safe, no-write onboarding
mcpsentinel scan http://localhost:8000/mcp
```

The first command you see is deliberately friendly and branded, while scan output stays free of decorative text when you select `json` or `sarif` for automation:

```text
$ mcpsentinel
+----------------------------------------------------------------+
|                          MCPSENTINEL                           |
|       Security review for Model Context Protocol servers        |
|                     Read-only by default                       |
+----------------------------------------------------------------+

Welcome to MCPSentinel 0.4.0

1. Run your first offline scan:
   mcpsentinel scan http://localhost:8000/mcp

2. Save CI-friendly output and fail on high-severity findings:
   mcpsentinel scan http://localhost:8000/mcp --format sarif --output results.sarif --fail-on high
```

| I want to… | Start here |
| --- | --- |
| inspect one local or remote server | [Scan a server](#scan-a-server) |
| add a review gate to CI | [GitHub Action](#github-action) |
| expose scanning to an AI client | [MCP-native scanner](#mcp-native-scanner) |
| run it in a container | [Container image](#container-image) |
| understand scope and limits | [What MCPSentinel can—and cannot—tell you](#what-mcpsentinel-canand-cannot-tell-you) |

### The review loop

```text
discover metadata  ->  static candidates  ->  semantic triage  ->  human review
                                                                        |
                                                                        v
                                                        explicitly approve baseline
```

## What you get

- MCP discovery over stdio and Streamable HTTP
- configurable static pattern rules for tool, prompt, and resource descriptors, including tool poisoning, shadowing, cross-server, and OAuth confused-deputy signals
- semantic triage: offline heuristic by default, optional OpenAI structured-output judge with bounded fallback
- explicit baseline approval and rug-pull definition diffs
- terminal, JSON, SARIF, and self-contained HTML risk reports
- allow/deny policy configuration
- explicit, Docker-sandboxed owned-tool validation with no network egress
- GitHub Action and MCP-native scanner interfaces

Static scans are metadata-only. Dynamic invocation is a separate opt-in path described below and never runs from the GitHub Action or MCP-native server.

## Install and onboard

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

# Use a repository-local directory for reviewed baseline snapshots
mcpsentinel scan http://localhost:8000/mcp --baseline-dir .mcpsentinel/baselines

# Create or replace a baseline only after reviewing the report
mcpsentinel scan http://localhost:8000/mcp --baseline-dir .mcpsentinel/baselines --approve-baseline
```

Baseline snapshots are kept in `~/.mcpsentinel/baselines` by default, but are **never updated by an ordinary scan**. A changed, added, or removed descriptor is surfaced as an `MCP-B001` rug-pull review finding while the prior approved snapshot is preserved. Review the report, then use `--approve-baseline` deliberately to create or replace the snapshot. This prevents an unattended scan from silently accepting a rug-pull change.

The first scan reports that no approved baseline exists. That is an onboarding state, not a vulnerability finding. Establish a baseline only from a server version and environment you trust.

The risk score is a capped 0–100 weighted sum of severity and semantic confidence. It is a prioritization signal, not a claim that the server is safe or unsafe in isolation.

## Semantic judges

`--judge heuristic` is the default and is fully offline. `--judge openai` requires `OPENAI_API_KEY`; `--judge auto` opts into using OpenAI when that key is present, otherwise it uses the heuristic. The OpenAI judge uses the Python SDK's Responses structured-output API, so an API response cannot bypass the scanner's expected verdict schema. Results are cached by descriptor hash plus a versioned judge/prompt identity in the baseline directory to avoid repeat API charges without retaining verdicts after judging methodology changes.

Each OpenAI judgement uses a 30-second client deadline and at most two SDK retries. Before an OpenAI request, MCPSentinel redacts common API keys, bearer credentials, private keys, and secret-valued JSON fields. Prompts are capped at 12,000 characters with field-aware head-and-tail excerpts, so a long descriptor cannot simply hide all final evidence behind filler. Candidate assessment uses a bounded concurrency of four requests. Redaction is defense-in-depth, not a guarantee that arbitrary sensitive metadata is safe to send. Choose `heuristic` when metadata must remain local.

If `--judge auto` encounters an OpenAI outage or malformed response, the scan completes with the offline heuristic and emits a visible report note; a fallback verdict is not cached as an OpenAI verdict. `--judge openai` remains strict and fails rather than silently changing the configured provider.

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

Before regex evaluation, the scanner applies Unicode NFKC normalization, removes format controls such as zero-width characters, and collapses whitespace in an analysis-only view. Original descriptor text remains unchanged in reports and baselines. It intentionally does not rewrite cross-script homoglyphs because that would risk misrepresenting legitimate metadata; use the benchmark to track those coverage gaps before claiming support for them.

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

The dynamic server image must already exist locally; MCPSentinel uses `--pull=never`. Every explicit tool invocation receives its own fresh container/session, so state from one selected tool cannot affect another. Docker is not needed for normal metadata scans. A dynamic response is retained only as a SHA-256 digest and content-type summary. If it resembles credential material, MCPSentinel reports `MCP-D001` without writing the response text to disk.

The repository includes a deliberately local-only Docker fixture to verify this boundary end to end. It is excluded from the normal test suite because it needs a running Docker daemon and builds an image:

```bash
MCPSENTINEL_RUN_DOCKER_TESTS=1 pytest tests/test_dynamic_docker_e2e.py
```

## GitHub Action

The repository root is a composite GitHub Action. It installs MCPSentinel, restores a scoped baseline cache, emits SARIF, and fails at the selected severity. It does not enable dynamic testing. Reference a release tag from another repository; pinning a full commit SHA is recommended for stricter supply-chain controls.

```yaml
- uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
- uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
  with:
    python-version: "3.12"
- uses: gentaArnezzi/MCPSentinel@v0.4.0
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

Action scans preserve an approved baseline by default. Use `approve-baseline: "true"` only in a reviewed workflow on a protected branch, after the scan's output is accepted. Do not enable it for pull requests from contributors.

```yaml
- uses: gentaArnezzi/MCPSentinel@v0.4.0
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  with:
    target: https://mcp.example.com/mcp
    transport: http
    approve-baseline: "true"
```

Set `OPENAI_API_KEY` in the workflow only when choosing `judge: openai` or `auto`; `heuristic` remains the default. For example, expose a GitHub Actions secret only to the scan step with `env: OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}`.

## MCP-native scanner

Run `mcpsentinel-mcp` to expose the scanner as the MCP tool `scan_mcp_server` over stdio. It is intentionally more constrained than the CLI: dynamic execution is unavailable, target configuration is operator-controlled, HTTP targets must be explicitly allowlisted, and stdio targets are disabled unless the operator enables them.

```bash
export MCPSENTINEL_ALLOWED_HOSTS="mcp.example.com,localhost"
mcpsentinel-mcp
```

The allowlist accepts either `host` or an exact `host:port`. HTTP redirects are refused, each discovery session has a 30-second deadline, and private or reserved addresses are denied by default. For public MCP-native HTTP scans, the validated DNS address set is pinned to the HTTP transport while the original hostname remains the HTTP Host and TLS SNI name; this prevents a second DNS lookup from changing a validated public hostname into an internal destination. For a deliberately trusted local network, set `MCPSENTINEL_ALLOW_PRIVATE_HTTP_TARGETS=true` alongside its exact allowlist entry.

Optional operator settings are `MCPSENTINEL_MCP_BASELINE_DIR`, `MCPSENTINEL_RULES_PATH`, `MCPSENTINEL_POLICY_PATH`, `MCPSENTINEL_MCP_JUDGE`, and `MCPSENTINEL_MCP_JUDGE_MODEL`. Set `MCPSENTINEL_ALLOW_STDIO_TARGETS=true` only in a trusted local environment. The MCP caller cannot choose arbitrary policy files, baseline paths, or approve a baseline. For a deliberate one-time approval, an operator can set `MCPSENTINEL_MCP_APPROVE_BASELINE=true`, execute the reviewed scan, then remove the variable.

## Registry publication

MCPSentinel is published to PyPI as [`mcp-guardian-scan`](https://pypi.org/project/mcp-guardian-scan/) and to the [official MCP Registry](https://registry.modelcontextprotocol.io/). The PyPI package has a different name because `mcpsentinel` was unavailable; the product name, import package, and CLI stay `MCPSentinel` and `mcpsentinel`.

The concrete [registry/server.json](registry/server.json) is kept version-locked with the package. The release workflow builds and audits the artifact, publishes it to PyPI through trusted publishing, then submits matching Registry metadata through GitHub OIDC. See [registry/README.md](registry/README.md) for release details and the official [package-type documentation](https://modelcontextprotocol.io/registry/package-types).

## Container image

Every non-prerelease GitHub Release publishes a versioned image and `latest` to GitHub Container Registry:

```bash
docker pull ghcr.io/gentaarnezzi/mcpsentinel:0.4.0
docker run --rm ghcr.io/gentaarnezzi/mcpsentinel:0.4.0 scan https://mcp.example.com/mcp --transport http
```

The first GHCR package may need its visibility set to **Public** in GitHub Packages by the repository owner. For local development, build the scanner image directly:

```bash
docker build -t mcpsentinel:local .
docker run --rm mcpsentinel:local scan https://mcp.example.com/mcp --transport http
```

The image intentionally has no Docker socket and cannot run the dynamic layer. Run dynamic validation from a trusted host with Docker configured.

## Dataset

[datasets/vulnerable_by_design](datasets/vulnerable_by_design) holds controlled descriptor-level ground truth for regression tests across every default static rule. It expands deterministically to **200 synthetic descriptors**: 35 hand-curated controls and 165 template-generated variants. It includes safe hard negatives, Unicode/zero-width evasion, non-English controls, metadata/schema variants, and intentionally uncovered controls; it contains no live third-party targets or runnable destructive payloads. [The labelling protocol](datasets/LABELING.md) documents the provenance and review contract.

Run a reproducible accuracy and timing measurement with the offline judge:

```bash
mcpsentinel benchmark datasets/vulnerable_by_design/manifest.json --format json --output benchmark.json
```

The benchmark measures both raw static candidates and semantic findings against the dataset's expected reportable rules. It reports precision, recall, false-positive rate, F1, confusion-matrix counts, stage timings, per-category breakdowns, and the count for each provenance type. Its JSON and terminal reports include the source-manifest SHA-256 and scanner version for traceability. Ten bounded-fetch controls intentionally count as static false positives but semantic true negatives, so regressions in noise suppression are visible in CI or release review.

On the bundled 200-case corpus with the offline heuristic and default threshold (`0.70`), static candidates measure precision `0.932`, recall `0.965`, F1 `0.948`, and false-positive rate `0.006` (`TP=136`, `FP=10`, `TN=1649`, `FN=5`). Semantic triage measures precision `1.000`, recall `0.965`, F1 `0.982`, and false-positive rate `0.000` (`TP=136`, `FP=0`, `TN=1659`, `FN=5`). The five deliberate misses—four non-English prompt-injection controls and one metadata-placement destructive-operation control—remain visible rather than being excluded. The SSRF category shows why both stages are reported: static precision is `0.545` while semantic precision is `1.000` on its controlled cases.

This is a reproducible regression signal—not a claim about public MCP-server accuracy, recall, real-world false-positive rate, or superiority over another scanner. The 165 generated variants are useful coverage controls, not 165 independent real-world observations.

For a real-world benchmark, collect only metadata that you are authorized to assess, preserve the source/version and independent reviewer labels, include benign and adversarial examples, freeze the rule and judge configuration, then compare the same labelled corpus against other scanners. Do not turn an unauthorised third-party scan into a vulnerability claim.

## What MCPSentinel can—and cannot—tell you

MCPSentinel is useful as a preflight signal for three workflows: an individual developer deciding whether to inspect an MCP server more deeply, a maintainer self-auditing metadata before release, and a security team adding a non-blocking or reviewed CI gate.

It discovers advertised MCP metadata; it does not read a server's source code, prove authorization boundaries, or guarantee that runtime behavior matches an honest description. A clean report is not proof that a server is safe. Dynamic validation is intentionally narrower still: it can only invoke explicitly named, high-confidence tools from an image you own, with arguments you supply. It is not a safe way to probe arbitrary public servers.

The default scanner is read-only. It never calls a discovered tool, follows HTTP redirects, or enables dynamic execution from the GitHub Action or MCP-native server. Use the result as evidence for review and combine it with source review, dependency review, permissions/egress controls, and normal incident response processes.

## Development

```bash
pytest
ruff check .
```

The project is intentionally dependency-light: `mcp` handles protocol discovery, while the core rule engine, snapshot store, and report writers use the standard library.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and supported-version information.
