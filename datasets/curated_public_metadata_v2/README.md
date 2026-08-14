# Curated public metadata benchmark v2

This is a 428-case, source-attributed **negative-control** benchmark for
ordinary public MCP tool metadata. It tests whether MCPSentinel reports an
unbounded-risk finding where the declared metadata does not itself advertise
one. It does not contact, invoke, dynamically test, or make vulnerability
claims about any upstream project or tool.

## Corpus and provenance

| Source | License | Pinned revision | Cases | Extraction |
| --- | --- | --- | ---: | --- |
| [AWS Labs MCP](https://github.com/awslabs/mcp) | Apache-2.0 | [`eff6cce`](https://github.com/awslabs/mcp/tree/eff6cce0ece95b65a6c4cf30b2fc9ed69f770ec7) | 329 | FastMCP tool name and first function-docstring paragraph |
| [GitHub MCP Server](https://github.com/github/github-mcp-server) | MIT | [`0ea1f77`](https://github.com/github/github-mcp-server/tree/0ea1f775a7c73eff1bd2e25904d01136756bbfe2) | 99 | Literal `mcp.Tool` name and default English `Description` |

Every case contains its source path, line, source-file SHA-256, source ID, and
source commit. The manifest contains only literal cases; it has no generated
case matrix. The extraction utility is
[`scripts/build_curated_benchmark.py`](../../scripts/build_curated_benchmark.py)
and takes two local checkouts, so reproduction does not access any running MCP
server.

## Labelling and interpretation

The corpus has one maintainer review and is explicitly marked
`independent-review-pending`. Its narrow rubric labels a rule only when the
metadata itself states that rule's **unbounded-risk condition**. A documented
tool that can delete or modify a scoped cloud resource is not automatically a
security vulnerability, and therefore has no expected MCPSentinel finding in
this negative-control corpus.

There are no labelled positive rule/case pairs. Precision, recall, and F1 are
therefore undefined (`n/a`), not 1.000. The meaningful measurement is the
false-positive rate and candidate count. Use the 200-case
[`vulnerable_by_design`](../vulnerable_by_design/README.md) corpus for
controlled positive/negative regression coverage. Do not combine their
metrics into a claim about public-server recall or scanner superiority.

Run it offline with the frozen heuristic:

```bash
mcpsentinel benchmark datasets/curated_public_metadata_v2/manifest.json \
  --judge heuristic --format json --output benchmark-v2.json
```

At the MCPSentinel 0.6.0 release configuration, the corpus produces zero static
candidates and zero semantic reports across 428 descriptors (3,852
descriptor/rule negative pairs), giving a false-positive rate of `0.000` for
this specific snapshot. An independent second review and a separately sourced
positive corpus remain necessary before making broader real-world accuracy
claims.
