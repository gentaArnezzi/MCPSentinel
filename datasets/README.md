# Vulnerable-by-design dataset

This directory contains controlled MCP descriptor ground truth for regression testing. It intentionally models documented MCP-risk classes without shipping runnable destructive behavior or scanning third-party services.

`manifest.json` expands deterministically to 200 descriptors: 35 hand-curated synthetic cases and 165 synthetic-template cases. A template matrix declares every dimension and its `expected_count`; the benchmark validates that count before measuring anything. Generated IDs, input order, and provenance are stable, and each report includes a SHA-256 digest of the source manifest and scanner version, so another reviewer can reproduce the exact corpus from the repository revision.

Each case defines a descriptor kind, untrusted metadata, ground-truth rule IDs, and—where applicable—the expected offline semantic judgement. The corpus deliberately includes safe hard negatives, Unicode/zero-width evasion, non-English controls, metadata/schema placement, and wording that only *claims* safeguards.

`expected_rules` is ground truth, not an assertion that the current static engine catches the case. `expected_reported_rules` is the expected post-triage result. The benchmark therefore makes false negatives and noise-suppression regressions visible instead of hiding gaps in rule coverage. Add a labelled case before adding or changing a detection rule so changes to precision, recall, and per-category false-positive rate remain reviewable.

Read [LABELING.md](LABELING.md) before extending the corpus. This is a transparent synthetic regression set, not independent evidence of real-world scanner accuracy or a competitor comparison.
