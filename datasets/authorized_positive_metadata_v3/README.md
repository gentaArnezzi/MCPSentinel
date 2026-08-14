# Authorized metadata positive benchmark v3

This is a 16-case, source-attributed **positive-control** corpus for
metadata-visible MCP prompt-injection and unbounded-code-execution scenarios.
It uses only Cisco's intentionally malicious, Apache-2.0 licensed evaluation
fixtures. No fixture is executed, no MCP server is started, and no endpoint is
contacted.

## Corpus and provenance

| Source | License | Pinned revision | Cases | Labelled rule/case pairs |
| --- | --- | --- | ---: | ---: |
| [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Apache-2.0 | [`893327c`](https://github.com/cisco-ai-defense/mcp-scanner/tree/893327c54d223ea07296f68f32d8294f5c045f4a) | 16 | 18 |

The source contributes ten fixtures from its `prompt-injection` directory and
six from `unauthorized-code-execution`. Cisco's directory names are the
first-party scenario labels; MCPSentinel maps them to `MCP001` and `MCP004`.
Two prompt-injection descriptions also explicitly advertise unrestricted
command execution and therefore carry both rule labels. Four code-execution
fixtures are deliberately excluded: their risky condition is exposed only in
source behavior, not in the advertised docstring, which this scanner does not
read.

Each case retains its exact repository commit, path, function line, source-file
SHA-256, and source-authored scenario label. The reproducible extractor is
[`scripts/build_authorized_positive_benchmark.py`](../../scripts/build_authorized_positive_benchmark.py).
It accepts a local checkout and produces literal JSON cases:

```bash
mcpsentinel benchmark datasets/authorized_positive_metadata_v3/manifest.json \
  --judge heuristic --format json --output benchmark-v3.json
```

## Interpretation

At the 0.7.0 release configuration, the frozen heuristic reports all 18
labelled pairs with no additional candidates. This result is useful as a
**regression guard only**: the selected v3 cases were used to calibrate the
new narrow `MCP001` and `MCP004` patterns. It is not held-out accuracy evidence
and must not be presented as public-server recall, real-world prevalence, or
superiority over another scanner.

V3 has one maintainer review and is marked `independent-review-pending`.
The source's own scenario labels are independent of MCPSentinel, but the
mapping into MCPSentinel rule IDs has not yet received a second human review.
Follow [`INDEPENDENT_REVIEW.md`](INDEPENDENT_REVIEW.md) before making a stronger
claim. The separate 428-case [v2 negative control](../curated_public_metadata_v2/README.md)
remains the false-positive check for these calibration changes.
