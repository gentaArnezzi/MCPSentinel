# MCPSentinel engineering assessment — 2026-09-21

Scope: local v0.8.8 release candidate based on repository commit
`1e3e572403ac9d6875783744c729404245330d76` (v0.8.7). This is an engineering
self-assessment, not an independent security audit or a production certification.
M8ven's assessed revision must be checked independently. Publication status is
tracked by the [release workflow](https://github.com/gentaArnezzi/MCPSentinel/actions/workflows/publish.yml)
and [releases](https://github.com/gentaArnezzi/MCPSentinel/releases), not inferred from this audit.

## Verdict

Useful today as a **metadata review and change-detection aid** for maintainers
and developer teams. The strongest use case is reviewing a known, authorized MCP
endpoint, approving its exact definition, and detecting unexpected subsequent
changes in CI. It is not a general source-code vulnerability scanner and cannot
decide whether an unknown executable is safe to start.

The local release candidate strengthens trust boundaries, instruction coverage,
dependency hygiene, and onboarding. Broad production readiness still needs a
successful release/CI validation, independent labeled testing,
and actual team feedback. Adding more rules or badges alone does not supply that evidence.

## What M8ven does and does not establish

The [live listing](https://m8ven.ai/mcp/gentaarnezzi/mcpsentinel) showed B, 89/100,
verified publisher, monitored source code, and no concerning findings when checked.
Its pinned commit is the v0.8.7 base above, not this release candidate.
It explicitly distinguishes repository assessment from unverified registry artifacts.

The [anonymous score JSON](https://m8ven.ai/api/mcp/score?url=https%3A%2F%2Fgithub.com%2FgentaArnezzi%2FMCPSentinel)
returned code subscore `100`, maintenance adjustment `0`, reputation adjustment
`-8`, adoption tier `unknown`, and `17 pass / 5 info / 0 warn / 0 fail`. The response
is explicitly reduced. It also mentioned one negative signal while the page said
no concerning findings. Its displayed adjustments do not fully explain 89, and the
page's generic C-cap text does not explain the displayed B. These need clarification
from M8ven; they do not justify inventing an A threshold or blaming a specific bug.

There are two factual listing corrections to propose to its maintainers:

- `OPENAI_API_KEY` is optional. Default `heuristic` mode works offline. Explicit
  `openai` mode requires the key and sends bounded, redacted metadata to OpenAI.
- The scanner is **served over stdio** but its MCP tool accepts only
  **operator-allowlisted HTTP targets**. Arbitrary stdio execution and dynamic
  invocation are not exposed through that tool. The CLI has a separate stdio mode.

“Read-only” means no discovered tool is invoked in a default scan. Discovery makes
network requests or starts a CLI-selected process; the scanner also writes local
cache files. It does not mean no side effects anywhere or OS-level isolation.
Neither the M8ven score nor an empty report proves detection accuracy or runtime safety.

## PRD implementation status

| Requirement | Current evidence | Boundary / remaining validation |
| --- | --- | --- |
| F1 static analysis | Nine default metadata rules; custom additive rules; tests for normalization and size limits | Pattern coverage only; not source/bytecode/CVE analysis |
| F2 intent analysis | Offline deterministic judge; optional OpenAI structured-output judge; independent MCP-S001 instruction review | Offline mode is not an LLM. No paid-provider end-to-end run in this audit; selected language patterns are not general multilingual understanding |
| F3 baseline / rug pull | Explicit matching-fingerprint approval; v5 snapshots; descriptor and stable identity drift; concurrent-write tests | Detects advertised changes, not malicious behavior hidden behind unchanged metadata |
| F4 CLI | Rich onboarding; actual-process demo tests; JSON and error exit codes | A stdio target executes on the host. Only launch code you trust |
| F5 SARIF | Report/schema tests and Action output path | GitHub upload and release-candidate CI still need a hosted run |
| F6 dynamic sandbox | Owned-tool opt-in; Docker constraints, unit tests, and real Docker E2E passed | Container is not a VM and no escape-proof claim is made |
| F7 GitHub Action | Fingerprint approval; base-branch cache restore; PR approval rejection; trusted-event save only | Hosted Action/cache behavior still requires CI validation; approval must use reviewed trusted workflows |
| F8 MCP-native | One constrained tool; target/egress guards; wrapper tests; registry metadata | Candidate registry/PyPI/GHCR versions not yet published or cross-verified |
| F9 reports | Rich, JSON, SARIF, rendered HTML; demo confirms templates are expanded | Risk score is prioritization, not a probability of compromise |
| F10 policy | Allow/deny configuration integrated with semantic candidates | Allow rules suppress findings by operator choice; they do not prove safety |

The original PRD's automatic progression to dynamic invocation was intentionally
replaced with explicit ownership and invocation approval. Its competitor
comparisons and accuracy superiority claims remain unverified hypotheses.

## Changes and local verification

| Check | Observed result |
| --- | --- |
| Ruff and `git diff --check` | Passed |
| Full suite with locked development dependencies and Docker enabled | 111 passed, none skipped (Docker Engine 29.7.2) |
| Full suite against installed wheel in a fresh environment | 110 passed, 1 Docker test skipped; imported from `site-packages`, not the source tree |
| Wheel + sdist build and Twine metadata checks | Passed |
| Distribution container build and non-root/read-only smoke tests | Passed; version 0.8.8; onboarding also runs with networking disabled |
| Locked dependency audit and installed dependency compatibility | No known vulnerabilities / no conflicts |
| Four offline benchmark runs | Completed; JSON evidence linked below |
| Hosted CI | [PR candidate run passed](https://github.com/gentaArnezzi/MCPSentinel/actions/runs/35602606329): tests, real Docker sandbox, distribution image, Action smoke |
| CodeQL | [Analysis passed](https://github.com/gentaArnezzi/MCPSentinel/actions/runs/35602606218); zero results across 50 rules; final release revision still requires its own passing checks |
| Registry publication | Separate release-workflow gate; not inferred from test success |

Fresh-wheel testing resolved allowed current dependency versions independently
of the development lock (including MCP 2.2.0); it does not establish support for
every historical version permitted by dependency ranges.

- PRs restore their target branch's baseline but cannot approve or save a new trusted
  state. Tests execute the actual Action shell guard and stop before installation.
- Every server instruction enters MCP-S001 even if no static rule fires. Selected
  multilingual override/concealment and negated-versus-mixed instruction regressions
  are covered. Semantic cache identity was bumped to `heuristic-v4`.
- Fingerprint v2 / snapshot v5 include server name, version, protocol, and advertised
  capability names. Identity changes produce MCP-B002. Legacy credentials prevent
  silent trust migration. Duplicate kind/name identities produce MCP-N002 and cannot
  be approved. Long/redacted identity collisions are distinguished by a digest.
- Snapshot/cache writes use unique temporary files, fsync, atomic replacement, and
  POSIX 0600 permissions. Concurrency regressions cover simultaneous writes/key creation.
- The locked HTTP stack was upgraded to httpx2/httpcore2 2.13.0 after the prior
  dependency audit flagged httpx2 2.10.0. `pip-audit` reports no known vulnerabilities
  for the current lock. That is a database check, not proof of no vulnerabilities.
- Added a CodeQL workflow; its hosted result must be checked separately. Remote
  `main` was initially unprotected. With the owner's approval, branch protection
  was then enabled: PR required, zero extra approving reviewers, strict required
  checks (`test`, `docker-sandbox-test`, `container-smoke-test`, `action-smoke-test`,
  and `Analyze Python`) bound to the GitHub Actions app, plus the `CodeQL` result
  check bound to GitHub's code-scanning app, administrator enforcement,
  and no force pushes or deletion. This was verified through the GitHub API; it is
  not a property inferred from committing a YAML file.
  Permissions were checked through Context7's GitHub Actions reference, with
  Python's no-build configuration checked against the
  [pinned CodeQL Action documentation](https://github.com/github/codeql-action/blob/ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd/README.md).
- Added a [local no-key demo](TRY_IT.md), real CLI/MCP integration tests, rendered HTML
  checks, benchmark filesystem error handling, and a [pilot feedback form](../.github/ISSUE_TEMPLATE/pilot-feedback.yml).

## Detection evidence

The [four benchmark reports](benchmarks/v0.8.8/README.md) include input hashes,
configuration, exact rule-pair counts, and descriptor-level counts. They cover 672
descriptors, not 672 servers, and are regression/calibration datasets.

- Synthetic: 137/142 labeled rule signals reported; five misses remain. On 60 benign
  descriptors, static analysis flags ten while the heuristic flags none.
- Public negative controls: no findings on 428 pinned descriptors from two source
  repositories. No positives means recall cannot be estimated.
- Authorized positive calibration: all 18 expected rule signals across 16 fixtures.
  These informed the detector and are not a held-out evaluation.
- Server instructions: all 27 expected rule signals across 28 curated cases, including
  ten negative descriptors. This small tuned set does not establish language-wide accuracy.

Benchmarks do not compare a competitor, test a live OpenAI judge, invoke third-party
servers, or establish representative end-to-end latency. Metadata claiming safeguards
can still hide unsafe code. Treat a clean result as “no reportable metadata signal,”
not approval to install untrusted software.

## Release and adoption gates

1. Run lint, the full tests, hash-locked dependency audit, wheel/sdist checks, and
   fresh-environment smoke tests on this candidate. Run Docker E2E, container smoke,
   Action smoke, and CodeQL in hosted CI before publishing.
2. Protect `main` against force pushes/deletion and require the selected CI checks.
   Choose review requirements that work for a single-maintainer project. Restrict
   release environment deployment and use trusted publishing.
3. Publish only the tested revision, then verify fresh installation from PyPI,
   GHCR digest, and MCP Registry version alignment. Confirm M8ven's assessed commit
   advances; request explanations for the listing inconsistencies above.
4. Recruit 5–10 consenting developer teams. Start with report-only CI, measure setup
   success/time, p50/p95 full-scan latency, actionable findings, false positives, and
   baseline-change usefulness. Ask for redacted reproductions, not private metadata.
5. Collect an independent held-out positive/negative evaluation, with at least two
   reviewers and disagreements recorded. Keep tuning data separate. Compare other
   scanners only at pinned versions, equivalent scope, and identical inputs.

Do not create artificial stars, downloads, contributors, or issues. Adoption and
independent review must be earned. M8ven owns its grade; these gates improve the
evidence available to developers but cannot guarantee A.
