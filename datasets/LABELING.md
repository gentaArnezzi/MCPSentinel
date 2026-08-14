# Dataset labelling protocol

## Scope and provenance

The bundled `vulnerable_by_design` corpus is a controlled synthetic regression
set. It never contains a live third-party server, real credentials, or a
runnable destructive payload. Every case declares one provenance value:

- `hand-curated-synthetic` — a manually written control.
- `synthetic-template` — a deterministic expansion of a documented matrix in
  `manifest.json`.

The benchmark prints these counts. A case matrix must declare `expected_count`;
the runner rejects it when the dimensions expand to a different number of
cases. This makes it possible to audit exactly what produced a metric from a
specific Git revision.

## Labelling rules

1. Treat `expected_rules` as the security ground truth for the descriptor, not
   as a promise that the present rules detect it.
2. Use `expected_reported_rules` for the post-triage expectation. For example,
   a bounded URL fetch can be a static `MCP003` candidate but expected to be
   withheld by the semantic judge.
3. State an explicit `semantic_outcome` whenever a static candidate is meant
   to be suppressed. Do not label a descriptor safe merely because it contains
   reassuring words such as "allowlist" or "confirmation".
4. Include both malicious controls and benign hard negatives for a changed
   rule. Keep obfuscation, language, schema/metadata placement, and ambiguous
   wording separate so a missed class is diagnosable.
5. Preserve intentionally uncovered cases. They are regression evidence for
   known coverage gaps, not test failures to delete.

## Review and changes

Before merging a corpus change, a maintainer should verify that the text is
synthetic or authorized, contains no secret material, has the right rule and
post-triage labels, and has a clear provenance. Run:

```bash
mcpsentinel benchmark datasets/vulnerable_by_design/manifest.json
pytest tests/test_dataset.py tests/test_benchmark.py
```

Record any metric change in the release notes or pull request. To make a
real-world claim, use a separately versioned, authorized corpus with source
versions and independent reviewer labels, then run each scanner with frozen
configuration against that same corpus. Do not infer public-server accuracy
from this bundled synthetic set.
