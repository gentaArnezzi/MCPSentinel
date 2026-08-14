# Vulnerable-by-design dataset

This directory contains controlled MCP descriptor ground truth for regression testing. It intentionally models documented MCP-risk classes without shipping runnable destructive behavior or scanning third-party services.

Each manifest case defines a tool name, untrusted metadata, expected static rule IDs, and—where applicable—the expected offline semantic judgement. Add a case before adding or changing a detection rule so precision/recall changes remain reviewable.
