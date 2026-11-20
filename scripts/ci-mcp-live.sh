#!/usr/bin/env bash
# Netra — the MCP server against a live controller (no cluster, no root, any OS)
#
# Real `netrad` and real `netra-mcp` (docs/mcp-integration.md), speaking newline-
# delimited JSON-RPC over the MCP server's stdio exactly as Claude Desktop or Hermes
# would. Asserts, from outside the processes:
#
#   read-only (default)  initialize; the read tools, prompts and resources are listed;
#                        a read tool returns the controller's real answer; NO mutating
#                        tool is listed and calling one is refused as unknown; a wrong
#                        API key surfaces as a tool error, not a crash; malformed input
#                        gets a JSON-RPC parse error and the server keeps serving.
#   mutations enabled    every mutating tool is listed (their names are read from the
#                        source, so a tool that fails to register is caught); adding a
#                        deny rule through MCP really changes the controller's config,
#                        the audit log names the MCP actor, deleting it undoes it, and
#                        bad arguments are tool errors that change nothing.
#
# Usage:
#   ./scripts/ci-mcp-live.sh
#   CONTROLLER_PORT=18090 ./scripts/ci-mcp-live.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BIN_DIR="${BIN_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/netra-mcp-bin.XXXXXX")}"
PORT="${CONTROLLER_PORT:-18090}"
API_KEY="ci-mcp-api-key"
AGENT_KEY="ci-mcp-agent-key"
URL="http://127.0.0.1:${PORT}"
LOG="$BIN_DIR/netrad.log"
command -v python3 >/dev/null || { echo "missing required command: python3" >&2; exit 1; }

echo "==> build netrad + netra-mcp"
CGO_ENABLED=0 go build -trimpath -o "$BIN_DIR/netrad" ./cmd/netrad
CGO_ENABLED=0 go build -trimpath -o "$BIN_DIR/netra-mcp" ./cmd/netra-mcp

NETRAD_PID=""
cleanup() {
  set +e
  if [[ -n "$NETRAD_PID" ]]; then
    kill "$NETRAD_PID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$NETRAD_PID" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$NETRAD_PID" 2>/dev/null
    wait "$NETRAD_PID" 2>/dev/null
  fi
  [[ "${KEEP:-}" == 1 ]] || rm -rf "$BIN_DIR"
}
trap cleanup EXIT

echo "==> start netrad on :${PORT}"
env NETRA_ALLOW_UNAUTHENTICATED=false NETRA_API_KEY="$API_KEY" NETRA_AGENT_KEY="$AGENT_KEY" NETRA_LISTEN=":${PORT}" \
  "$BIN_DIR/netrad" >"$LOG" 2>&1 &
NETRAD_PID=$!
for _ in $(seq 1 60); do
  curl -sf -H "Authorization: Bearer ${API_KEY}" "${URL}/api/v1/status" >/dev/null 2>&1 && break
  kill -0 "$NETRAD_PID" 2>/dev/null || { echo "netrad exited early:" >&2; tail -n 50 "$LOG" >&2; exit 1; }
  sleep 0.25
done
curl -sf -H "Authorization: Bearer ${API_KEY}" "${URL}/api/v1/status" >/dev/null 2>&1 || { echo "controller never ready" >&2; tail -n 50 "$LOG" >&2; exit 1; }

# The number of mutating tools, read from the source: the two registration styles
# are a table of `name:` entries and individual `Name:` fields.
MUTATING="$(grep -oE '^[[:space:]]+(name|Name):[[:space:]]+"netra_[a-z0-9_]+"' cmd/netra-mcp/tools_mutate.go | grep -oE 'netra_[a-z0-9_]+' | sort -u | tr '\n' ' ')"
echo "    mutating tools in source: $(wc -w <<<"$MUTATING" | tr -d ' ')"

BIN_DIR="$BIN_DIR" URL="$URL" API_KEY="$API_KEY" MUTATING="$MUTATING" python3 - <<'PY'
import json, os, subprocess, sys, urllib.request

BIN = os.environ["BIN_DIR"] + "/netra-mcp"
URL, KEY = os.environ["URL"], os.environ["API_KEY"]
MUTATING = set(os.environ["MUTATING"].split())
failures = []

def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("  FAIL:", msg)
    return cond

class MCP:
    """One netra-mcp process; one request line, one response line."""
    def __init__(self, **env):
        e = dict(os.environ, NETRA_URL=URL, NETRA_API_KEY=KEY, NETRA_MCP_ALLOW_MUTATIONS="false")
        e.update(env)
        self.p = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e, text=True, bufsize=1)
        self.n = 0
    def raw(self, line):
        self.p.stdin.write(line + "\n"); self.p.stdin.flush()
        out = self.p.stdout.readline()
        if not out:
            raise RuntimeError("netra-mcp closed stdout: " + self.p.stderr.read())
        return json.loads(out)
    def call(self, method, params=None):
        self.n += 1
        return self.raw(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}))
    def tool(self, name, args=None):
        return self.call("tools/call", {"name": name, "arguments": args or {}})
    def notify(self, method):
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n"); self.p.stdin.flush()
    def close(self):
        self.p.stdin.close()
        try:
            rc = self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill(); rc = -9
        return rc

def http(path, method="GET"):
    r = urllib.request.Request(URL + path, method=method, headers={"Authorization": "Bearer " + KEY})
    with urllib.request.urlopen(r, timeout=10) as resp:
        return json.loads(resp.read())

def text_of(resp):
    return "".join(c.get("text", "") for c in resp["result"]["content"])

# ---- read-only ------------------------------------------------------------------
print("==> read-only server")
ro = MCP()
init = ro.call("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "ci", "version": "0"}})
check(init["result"]["serverInfo"]["name"] == "netra-mcp", "initialize: serverInfo.name")
check(init["result"]["protocolVersion"], "initialize: protocolVersion")
ro.notify("notifications/initialized")   # a notification gets no response line

ro_tools = {t["name"]: t for t in ro.call("tools/list")["result"]["tools"]}
check(len(ro_tools) >= 60, f"read-only server lists {len(ro_tools)} tools, want at least 60")
for t in ro_tools.values():
    check(t.get("description") and t.get("inputSchema", {}).get("type") == "object", f"tool {t['name']} lacks a description or object schema")
check("netra_status" in ro_tools, "netra_status is listed")
leaked = sorted(MUTATING & set(ro_tools))
check(not leaked, f"read-only server lists mutating tools: {leaked}")
check(len(MUTATING) >= 50, f"only {len(MUTATING)} mutating tools found in the source: the extraction is broken")

prompt_names = {p["name"] for p in ro.call("prompts/list")["result"]["prompts"]}
check(len(prompt_names) > 0, "no prompts listed")
check("netra_tls_triage" in prompt_names, "netra_tls_triage prompt missing")
check("netra_congestion_triage" in prompt_names, "netra_congestion_triage prompt missing")
res = ro.call("resources/list")["result"]["resources"]
check(len(res) > 0, "no resources listed")
uris = {r["uri"] for r in res}
check("netra://ebpf/tls-risk" in uris, "netra://ebpf/tls-risk resource missing")
check("netra://ai/congestion" in uris, "netra://ai/congestion resource missing")
tls_risk = ro.call("resources/read", {"uri": "netra://ebpf/tls-risk"})
check("error" not in tls_risk, f"resources/read tls-risk errored: {tls_risk.get('error')}")

st = ro.tool("netra_status")
check("error" not in st, f"netra_status returned a JSON-RPC error: {st.get('error')}")
if "result" in st:
    body = text_of(st)
    check(body.strip() != "", "netra_status returned no content")
    try:
        json.loads(body)
    except ValueError:
        check(False, f"netra_status content is not JSON: {body[:120]!r}")

refused = ro.tool("netra_ebpf_deny_add", {"ip": "203.0.113.50"})
check("error" in refused and "unknown tool" in refused["error"]["message"], f"a mutating tool on a read-only server must be unknown, got {refused}")
check(not any(r.get("ip") == "203.0.113.50" for r in http("/api/v1/ebpf/config").get("blocked", []) if isinstance(r, dict)) and "203.0.113.50" not in json.dumps(http("/api/v1/ebpf/config")), "the refused deny_add still changed the controller")

# Malformed input is an error response, and the server keeps going.
bad = ro.raw("{this is not json")
check(bad.get("error", {}).get("code") == -32700, f"malformed line: want parse error -32700, got {bad}")
check("result" in ro.call("tools/list"), "server stopped answering after a malformed line")
check(ro.call("no/such/method").get("error", {}).get("code") == -32601, "unknown method: want -32601")
check(ro.close() == 0, "read-only server did not exit cleanly on EOF")

# ---- wrong credentials ----------------------------------------------------------
print("==> a wrong API key is a tool error, not a crash")
wrong = MCP(NETRA_API_KEY="not-the-key")
r = wrong.tool("netra_status")
check(("error" in r) or r["result"].get("isError") is True, f"wrong key: want a tool error, got {r}")
check("401" in json.dumps(r) or "auth" in json.dumps(r).lower(), f"wrong key: the error should say why: {json.dumps(r)[:200]}")
check("result" in wrong.call("tools/list"), "server died after an authentication failure")
wrong.close()

# ---- mutations enabled ----------------------------------------------------------
print("==> mutations enabled")
rw = MCP(NETRA_MCP_ALLOW_MUTATIONS="true", NETRA_MCP_ACTOR="mcp:ci-live")
rw.call("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "ci", "version": "0"}})
rw_tools = {t["name"] for t in rw.call("tools/list")["result"]["tools"]}
added = rw_tools - set(ro_tools)
check(ro_tools.keys() <= rw_tools, "enabling mutations removed a read tool")
check(added == MUTATING, f"mutating tools differ from the source: missing {sorted(MUTATING - added)}, unexpected {sorted(added - MUTATING)}")
check({"netra_ebpf_deny_add", "netra_ebpf_deny_delete", "netra_policy_apply"} <= rw_tools, "the core mutating tools are not listed")

IP = "203.0.113.77"
add = rw.tool("netra_ebpf_deny_add", {"ip": IP, "direction": "egress"})
check("error" not in add and not add["result"].get("isError"), f"deny_add failed: {add}")
check(IP in json.dumps(http("/api/v1/ebpf/config")), "the deny rule added through MCP is not in the controller's config")
audit = http("/api/v1/audit?limit=50")["items"]
mine = [e for e in audit if e.get("actor") == "mcp:ci-live"]
check(mine, f"no audit event carries the MCP actor; actors seen: {sorted({e.get('actor') for e in audit})}")
check(any(IP in json.dumps(e) for e in mine), "the audit event for the MCP change does not mention the address")

bad_ip = rw.tool("netra_ebpf_deny_add", {"ip": "not-an-ip"})
check("error" in bad_ip or bad_ip["result"].get("isError") is True, f"an invalid address must be a tool error: {bad_ip}")
missing = rw.tool("netra_ebpf_deny_add", {})
check("error" in missing or missing["result"].get("isError") is True, f"a missing required argument must be an error: {missing}")
check("not-an-ip" not in json.dumps(http("/api/v1/ebpf/config")), "an invalid address reached the controller's config")

dele = rw.tool("netra_ebpf_deny_delete", {"ip": IP})
check("error" not in dele and not dele["result"].get("isError"), f"deny_delete failed: {dele}")
check(IP not in json.dumps(http("/api/v1/ebpf/config")), "the deny rule is still in the controller's config after the MCP delete")
rw.close()

if failures:
    print(f"\n{len(failures)} check(s) failed", file=sys.stderr)
    sys.exit(1)
print("all MCP checks passed")
PY

echo "==> PASS mcp live"
