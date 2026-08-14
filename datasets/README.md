# Vulnerable-by-design dataset

This directory contains controlled MCP descriptor ground truth for regression testing. It intentionally models documented MCP-risk classes without shipping runnable destructive behavior or scanning third-party services.

Each manifest case defines a descriptor kind, untrusted metadata, ground-truth rule IDs, and—where applicable—the expected offline semantic judgement. The corpus deliberately includes safe hard negatives, Unicode/zero-width evasion, non-English controls, metadata/schema placement, and wording that only *claims* safeguards.

`expected_rules` is ground truth, not an assertion that the current static engine catches the case. The benchmark therefore makes false negatives visible instead of hiding gaps in rule coverage. Add a labelled case before adding or changing a detection rule so changes to precision, recall, and per-category false-positive rate remain reviewable.
