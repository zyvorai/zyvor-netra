---
sidebar_position: 6
---

# MCP Registry

`netra-mcp`, the stdio MCP server for AI agents, is listed in the
[MCP Registry](https://registry.modelcontextprotocol.io) as `io.github.zyvorai/netra` (published
with v0.30.1). Look up the live entry:

```
https://registry.modelcontextprotocol.io/v0.1/servers/io.github.zyvorai%2Fnetra/versions/latest
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

## Use it

You need a running Netra controller and an API key; the MCP server only bridges to the
controller's HTTP API.

**Claude Code**

```
claude mcp add netra \
  -e NETRA_URL=https://<controller>:30870 \
  -e NETRA_API_KEY=<key> \
  -- docker run -i --rm -e NETRA_URL -e NETRA_API_KEY ghcr.io/zyvorai/netra-mcp:0.30.1
```

**Claude Desktop or any stdio client:** use the JSON above. Restart the client and the `netra_*`
tools appear.

Then ask in plain language, for example:

- "Why are `payments-api` connections timing out?"
- "Which kernel function is dropping traffic from namespace `prod`?"
- "Show TCP retransmission anomalies."
- "What changed in the network path in the last 30 minutes?"
- "Draft a containment rule for this IP, but don't apply it."

Notes:

- Inside the container `127.0.0.1` is the container itself: use the node's address, or
  `--network host`.
- For a lab controller with a self-signed certificate set `NETRA_TLS_INSECURE=true`.
- Set `NETRA_MCP_ACTOR` to something that identifies you or the agent; it is recorded in the audit
  log.

Quick check without a client (works even with no controller; real tool calls need `NETRA_URL` and
the key):

```
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
| docker run -i --rm -e NETRA_URL -e NETRA_API_KEY ghcr.io/zyvorai/netra-mcp:0.30.1
```

## Read tools and mutating tools

The server exposes 190 tools: 130 read tools and 60 opt-in mutating tools. With
`NETRA_MCP_ALLOW_MUTATIONS` unset or `false` (the default), only read tools are registered; the
mutating tool names do not exist in the running process.

Enabling mutations changes nothing else about the safety model:

- Policy apply still needs a plan token and a risk confirmation.
- Enforcement stays lease-bounded and fails open to observe.

Details, the full tool list and other client setups are in the
[MCP integration guide](https://github.com/zyvorai/zyvor-netra/blob/main/docs/mcp-integration.md#install-from-the-mcp-registry-oci).
