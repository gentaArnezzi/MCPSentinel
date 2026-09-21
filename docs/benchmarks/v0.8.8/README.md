# v0.8.8 local benchmark evidence

Generated on 2026-09-21 with Python 3.12, `heuristic-v4`, threshold `0.70`.
These are release-candidate measurements, not independent evaluations.
Each JSON records its input manifest SHA-256. Stage timings are one local run,
not p50/p95 latency and not full network discovery time. No API calls were used.

| Dataset | Descriptors | Semantic rule pairs TP / FP / FN | Semantic descriptors TP / FP / TN / FN |
| --- | ---: | --- | --- |
| [Synthetic regression](synthetic.json) | 200 | 137 / 0 / 5 | 135 / 0 / 60 / 5 |
| [Public negative control](public-negative.json) | 428 | 0 / 0 / 0 | 0 / 0 / 428 / 0 |
| [Authorized positive calibration](authorized-positive.json) | 16 | 18 / 0 / 0 | 16 / 0 / 0 / 0 |
| [Server instructions](server-instructions.json) | 28 | 27 / 0 / 0 | 18 / 0 / 10 / 0 |

The four datasets total 672 descriptors, **not 672 independent MCP servers**.
V2 contains two source repositories. V3 and instruction controls informed the
detector and therefore cannot be used as a held-out accuracy claim. Synthetic
template variants are correlated. Zero observed false positives is not a promise
of zero production false positives. V2 has no positives, so recall/precision/F1
are unavailable; V3 has no negative descriptors, so descriptor FPR is unavailable.

Rule-pair metrics test exact labels but include inactive rule/descriptor pairs in
their negatives. Descriptor metrics use one decision per descriptor but do not
distinguish a correct rule from an unrelated finding on a positive descriptor.
Read both, along with category/segment results and the labeling protocols.

Reproduce from the repository root after installing this checkout:

```bash
mcpsentinel benchmark datasets/vulnerable_by_design/manifest.json --format json --output docs/benchmarks/v0.8.8/synthetic.json
mcpsentinel benchmark datasets/curated_public_metadata_v2/manifest.json --format json --output docs/benchmarks/v0.8.8/public-negative.json
mcpsentinel benchmark datasets/authorized_positive_metadata_v3/manifest.json --format json --output docs/benchmarks/v0.8.8/authorized-positive.json
mcpsentinel benchmark datasets/server_instructions_v4/manifest.json --format json --output docs/benchmarks/v0.8.8/server-instructions.json
```
