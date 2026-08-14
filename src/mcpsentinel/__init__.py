"""MCPSentinel: precision-first security scanning for MCP servers."""

from .models import ScanReport
from .version import __version__

__all__ = ["ScanReport", "__version__"]
