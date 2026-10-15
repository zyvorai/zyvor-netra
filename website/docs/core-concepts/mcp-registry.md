---
sidebar_position: 6
---

# MCP Registry

`netra-mcp`, the stdio MCP server for AI agents, is set up to be listed in the
[MCP Registry](https://registry.modelcontextprotocol.io) as `io.github.zyvorai/netra`. The entry
is published from the v0.30.1 release; once published you can look it up with:

```
https://registry.modelcontextprotocol.io/v0/servers?search=io.github.zyvorai/netra
```

| | |
|---|---|
| Registry name | `io.github.zyvorai/netra` |
| Image | `ghcr.io/zyvorai/netra-mcp:0.30.1` (multi-arch, cosign-signed) |
| Transport | stdio |

## Client configuration

Any stdio MCP client can run the image directly:

```json
{
  "mcpServers": {
    "netra": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
               "-e", "NETRA_URL", "-e", "NETRA_API_KEY",
               "ghcr.io/zyvorai/netra-mcp:0.30.1"],
      "env": { "NETRA_URL": "https://netra.example:30870", "NETRA_API_KEY": "..." }
    }
  }
}
```

| Variable | Default | Purpose |
|---|---|---|
| `NETRA_URL` | `https://127.0.0.1:30870` | Base URL of the Netra controller |
| `NETRA_API_KEY` | unset | Bearer token matching the controller's `NETRA_API_KEY` |
| `NETRA_MCP_ALLOW_MUTATIONS` | `false` | Registers the opt-in mutating tools when `true` |
| `NETRA_MCP_ACTOR` | `mcp:hermes` | Recorded as `X-Netra-Actor`, so agent actions are distinct in the audit log |

## Read tools and mutating tools

The server exposes 189 tools: 129 read tools and 60 opt-in mutating tools. With
`NETRA_MCP_ALLOW_MUTATIONS` unset or `false` (the default), only read tools are registered; the
mutating tool names do not exist in the running process.

Enabling mutations changes nothing else about the safety model:

- Policy apply still needs a plan token and a risk confirmation.
- Enforcement stays lease-bounded and fails open to observe.

Details, the full tool list and other client setups are in the
[MCP integration guide](https://github.com/zyvorai/zyvor-netra/blob/main/docs/mcp-integration.md#install-from-the-mcp-registry-oci).
