# Official MCP Registry release metadata

`server.json` is the ready-to-submit metadata for the official MCP Registry’s PyPI package type. Its server name, repository URL, and package README ownership marker are already aligned with `gentaArnezzi/MCPSentinel`:

```html
<!-- mcp-name: io.github.gentaArnezzi/mcpsentinel -->
```

The public PyPI distribution is named `mcp-guardian-scan` because PyPI rejected `mcpsentinel` as confusable with an existing project. The product name, import package, and CLI remain MCPSentinel and `mcpsentinel` respectively.

For the first release, configure the PyPI **pending** trusted publisher with these exact values:

| Field | Value |
| --- | --- |
| PyPI Project Name | `mcp-guardian-scan` |
| Owner | `gentaArnezzi` |
| Repository name | `MCPSentinel` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

Then create the GitHub environment named `pypi` and protect it with any reviewers you want to approve releases. Publishing a GitHub Release for a version tag such as `v0.8.2` runs [`.github/workflows/publish.yml`](../.github/workflows/publish.yml). It tests and builds the package, publishes to PyPI using OIDC, then submits the matching `registry/server.json` using GitHub OIDC. No package token, Registry token, or password is stored in GitHub.

For every later release, update the package and Registry versions together before creating the matching `vX.Y.Z` GitHub Release. The workflow rejects a release if the tag, `pyproject.toml`, and `registry/server.json` do not agree.

For a local pre-release check:

```bash
uv build
uvx twine check dist/*
```

PyPI converts the pending publisher to an ordinary trusted publisher after the first successful publication. Until that happens, the package name is not reserved.
