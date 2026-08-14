# Official MCP Registry release metadata

`server.json.template` is a release-ready template for the official MCP Registry’s PyPI package type. Before publishing, replace every `YOUR_GITHUB_USERNAME` placeholder, set the actual published package/version, and add the matching line below to the PyPI package README:

```html
<!-- mcp-name: io.github.YOUR_GITHUB_USERNAME/mcpsentinel -->
```

Then validate it with the current `mcp-publisher` tool, authenticate to the namespace you control, and publish. Registry publication is intentionally not automated here because it requires the owner’s PyPI and registry credentials and produces an externally visible, immutable release.
