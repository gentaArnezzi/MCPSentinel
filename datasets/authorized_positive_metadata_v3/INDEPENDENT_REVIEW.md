# Independent review protocol for Benchmark v3

V3 must remain `independent-review-pending` until a person who did not create
the corpus completes this checklist and records their review in a pull request
or release note.

1. Clone Cisco's repository at commit
   `893327c54d223ea07296f68f32d8294f5c045f4a`; inspect only the 16 source paths
   named in the manifest. Do not execute a fixture or install its dependencies.
2. Confirm the source repository's Apache-2.0 license, the scenario directory
   label, function name, docstring, line, and source-file SHA-256 for every
   case.
3. Confirm that each `MCP001` label represents a directive to override,
   disable, bypass, or evade agent safety/instructions, and each `MCP004`
   label represents metadata-visible unbounded code or command execution.
4. Confirm the two dual-labelled prompt-injection cases independently expose
   unrestricted command execution, not merely an implementation detail.
5. Rebuild and compare the manifest byte-for-byte:

   ```bash
   uv run python scripts/build_authorized_positive_benchmark.py \
     --source-root /path/to/mcp-scanner \
     --output /tmp/benchmark-v3.json
   cmp /tmp/benchmark-v3.json datasets/authorized_positive_metadata_v3/manifest.json
   ```

6. Run the v3 corpus and the v2 public negative control. Record both results;
   do not report v3's calibration score without v2's false-positive result.

   ```bash
   mcpsentinel benchmark datasets/authorized_positive_metadata_v3/manifest.json
   mcpsentinel benchmark datasets/curated_public_metadata_v2/manifest.json
   ```

When complete, update `reviewer_count`, `review_status`, and the release notes
with the independent review record. Do not change source labels to improve a
metric; open a separate discussion for contested labels.
