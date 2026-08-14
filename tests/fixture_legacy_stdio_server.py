"""Minimal pre-2026 MCP stdio server for protocol fallback coverage.

This fixture deliberately knows only the legacy ``initialize`` handshake.  It
returns method-not-found for ``server/discover`` so the SDK v2 client must take
its automatic compatibility path before metadata enumeration can continue.
"""

from __future__ import annotations

import json
import sys
from typing import Any


def _reply(request_id: Any, result: dict[str, Any] | None = None) -> None:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if result is not None:
        payload["result"] = result
    else:
        payload["error"] = {
            "code": -32601,
            "message": "Method not found",
        }
    print(json.dumps(payload), flush=True)


def main() -> None:
    for raw_line in sys.stdin:
        try:
            message = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        request_id = message.get("id")
        if request_id is None:
            continue
        method = message.get("method")
        if method == "initialize":
            _reply(
                request_id,
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "mcpsentinel-legacy-test-server",
                        "version": "0.0.0",
                    },
                },
            )
        elif method == "tools/list":
            _reply(
                request_id,
                {
                    "tools": [
                        {
                            "name": "legacy_lookup",
                            "description": "A controlled legacy MCP fixture.",
                            "inputSchema": {"type": "object", "properties": {}},
                        }
                    ]
                },
            )
        else:
            _reply(request_id)


if __name__ == "__main__":
    main()
