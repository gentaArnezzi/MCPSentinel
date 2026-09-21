# Try MCPSentinel locally

Use a Python 3.12+ environment. Clone this repository, enter its directory, then
install the package with `python -m pip install mcp-guardian-scan`.
For an unreleased checkout, use `python -m pip install -e .` instead.

The included demo advertises metadata only. It has no tool invocation handler,
credentials, external API, or Docker requirement.

## 1. Inspect a clean catalog

```bash
mcpsentinel scan "python examples/demo_server.py" --transport stdio --baseline-dir .demo-baseline
```

Expect no findings and a missing baseline notice. Copy the displayed definition
fingerprint, inspect the catalog, and approve that exact fingerprint:

```bash
mcpsentinel baseline approve "python examples/demo_server.py" --transport stdio \
  --baseline-dir .demo-baseline --fingerprint sha256:REPLACE_WITH_REVIEWED_FINGERPRINT
```

Repeat the first scan. Expect `Baseline: unchanged`. Keep the target command and
environment the same: changing them selects a different authentication/target scope.

## 2. See a finding without executing an attack

```bash
mcpsentinel scan "python examples/demo_server.py --scenario review" --transport stdio \
  --baseline-dir .demo-baseline --fail-on high
```

Expect `MCP-S001` for Spanish instruction override/concealment and exit code 1.
The malicious text is a fixture; nothing executes it. This is a separate target
scope, so its baseline will initially be missing.

## 3. Inspect an ambiguous catalog

```bash
mcpsentinel scan "python examples/demo_server.py --scenario duplicate" --transport stdio \
  --baseline-dir .demo-baseline
```

Expect `MCP-N002` and `Baseline: ambiguous`. Approval of that catalog is refused.

## 4. Save the actual HTML report

```bash
mcpsentinel scan "python examples/demo_server.py --scenario review" --transport stdio \
  --baseline-dir .demo-baseline --format html --output demo-report.html
```

Open `demo-report.html` in your browser. Do not open
`src/mcpsentinel/templates/risk_report.html`: that is the Jinja source template,
not a completed scan report. To capture terminal colors, run
`mcpsentinel --color always scan ...` in your terminal.

## Pilot it in your team

Start with `fail-on: none` in CI, review every finding, then choose a severity gate.
Record scanner version, judge, latency, and whether each finding was useful or
incorrect. Do not submit credentials or private server metadata in public issues.
Use the [pilot feedback template](../.github/ISSUE_TEMPLATE/pilot-feedback.yml)
to report results. A clean metadata scan does not validate server runtime behavior.
