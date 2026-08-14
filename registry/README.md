# Official MCP Registry release metadata

`server.json` is the ready-to-submit metadata for the official MCP Registry’s PyPI package type. Its server name, repository URL, and package README ownership marker are already aligned with `gentaArnezzi/MCPSentinel`:

```html
<!-- mcp-name: io.github.gentaArnezzi/mcpsentinel -->
```

For each release, update the package and registry versions together, build and upload the package to PyPI, then validate and submit the metadata:

```bash
uv build
uvx twine check dist/*
uvx twine upload dist/*
mcp-publisher login github
mcp-publisher publish registry/server.json
```

Registry publication is intentionally not automated here because it requires the owner’s PyPI and Registry credentials and produces an externally visible, immutable release.
