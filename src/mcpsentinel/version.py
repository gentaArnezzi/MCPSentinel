"""Runtime version derived from installed package metadata."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

_DISTRIBUTION_NAME = "mcp-guardian-scan"

try:
    __version__ = version(_DISTRIBUTION_NAME)
except PackageNotFoundError:  # pragma: no cover - source-tree fallback only
    __version__ = "0+unknown"
