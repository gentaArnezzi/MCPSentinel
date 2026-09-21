# Server-instruction intent corpus

This curated, metadata-only corpus exercises the first-class `MCP-S001` server-instruction
review path. It contains 28 cases: five benign and five malicious English instructions, five
benign and five malicious non-English instructions, four normalization/obfuscation cases, and
four deliberately ambiguous outbound-transfer instructions.

The corpus is a transparent regression control, not an independently reviewed or statistically
representative sample of the MCP ecosystem. It contains no live endpoint, credential, tool call,
or executable destructive payload. Segment metrics in the benchmark report measure only the
dedicated `MCP-S001` verdict, while overall metrics still include any static rules that match the
same metadata.

Run it with:

```bash
mcpsentinel benchmark datasets/server_instructions_v4/manifest.json --judge heuristic
```
