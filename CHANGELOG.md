# Changelog

## 0.8.8 — Security hardening (2026-09-21)

- Scope GitHub Action baseline caches to a pull request's base branch and make pull requests restore-only.
- Independently review every MCP server instruction through `MCP-S001`, with precision-first offline multilingual coverage and policy/cache integration.
- Upgrade definition fingerprints to v2 and baseline snapshots to v5 so stable server name, version, protocol, and capability drift produces `MCP-B002`.
- Require explicit reapproval for old snapshot formats, and refuse to trust a legacy snapshot when its authentication scope cannot be proven.
- Report duplicate descriptor identities as `MCP-N002` and refuse ambiguous baseline approval.
- Make baseline and semantic-cache writes concurrency-safe, atomic, durable, and private on POSIX systems.
- Add adversarial regression coverage plus a 28-case segmented server-instruction benchmark corpus.
- Add CodeQL analysis as an independent GitHub security workflow.
- Upgrade the locked HTTP client stack to httpx2/httpcore2 2.13.0 and require httpx2 >=2.12 to address the dependency audit findings.
- Distinguish bounded prohibitions from mixed malicious server instructions; cover standalone concealment and instruction override in regression tests.
- Report descriptor-level benchmark metrics alongside rule-pair metrics, so inactive rules do not obscure the false-positive denominator.
- Add a metadata-only local demo with CLI integration tests and a structured pilot feedback template.
- Include discovery in scan timestamps, create benchmark output directories, and return actionable CLI errors for filesystem failures.

This is the final planned scanner hardening release before a feature freeze focused on external evaluation and adoption evidence.

## 0.8.7

- Added MCP v2 discovery with automatic legacy negotiation fallback and server-instruction discovery.
- Hardened authentication-scoped baseline keys, resource normalization, release workflows, and the GitHub Action failure/report flow.
