// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/mcpserver"
)

// rpcLine mirrors the shape used by internal/mcpserver's own tests, kept
// local here since it's unexported there.
type rpcLine struct {
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

type toolCallResult struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

func callTool(t *testing.T, c *client, allowMutations bool, name string, args map[string]any) toolCallResult {
	t.Helper()
	srv, err := buildServer(c, allowMutations)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": name, "arguments": args},
	}
	line, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	in := bytes.NewReader(append(line, '\n'))
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	var resp rpcLine
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", out.String(), err)
	}
	if len(resp.Error) > 0 && string(resp.Error) != "null" {
		t.Fatalf("unexpected protocol error: %s", resp.Error)
	}
	var result toolCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal tool result: %v", err)
	}
	return result
}

func testClient(t *testing.T, ts *httptest.Server) *client {
	t.Helper()
	t.Setenv("NETRA_URL", ts.URL)
	t.Setenv("NETRA_API_KEY", "")
	t.Setenv("NETRA_TLS_INSECURE", "")
	t.Setenv("NETRA_MCP_ACTOR", "mcp:test")
	return newClient()
}

func TestReadTool_Status(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/status" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Netra-Actor"); got != "mcp:test" {
			t.Errorf("expected X-Netra-Actor mcp:test, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":"0.20.0"}`))
	}))
	defer ts.Close()

	c := testClient(t, ts)
	result := callTool(t, c, false, "netra_status", map[string]any{})
	if result.IsError {
		t.Fatalf("expected success, got error result: %+v", result)
	}
	if !strings.Contains(result.Content[0].Text, "0.20.0") {
		t.Fatalf("unexpected content: %s", result.Content[0].Text)
	}
}

func TestReadTool_AuditWithLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("limit"); got != "10" {
			t.Errorf("expected limit=10, got %q", got)
		}
		w.Write([]byte(`{"items":[]}`))
	}))
	defer ts.Close()

	c := testClient(t, ts)
	callTool(t, c, false, "netra_audit", map[string]any{"limit": 10})
}

func TestMutatingPair_CIDRAddDelete(t *testing.T) {
	var gotAddBody, gotDeleteBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/api/v1/ebpf/cidr":
			gotAddBody = body
		case "/api/v1/ebpf/cidr/delete":
			gotDeleteBody = body
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(`{"mode":"observe"}`))
	}))
	defer ts.Close()

	c := testClient(t, ts)
	callTool(t, c, true, "netra_ebpf_cidr_add", map[string]any{"cidr": "10.0.0.0/8", "direction": "egress"})
	callTool(t, c, true, "netra_ebpf_cidr_delete", map[string]any{"cidr": "10.0.0.0/8", "direction": "egress"})

	if gotAddBody["cidr"] != "10.0.0.0/8" || gotAddBody["direction"] != "egress" {
		t.Fatalf("unexpected add body: %+v", gotAddBody)
	}
	if gotDeleteBody["cidr"] != "10.0.0.0/8" {
		t.Fatalf("unexpected delete body: %+v", gotDeleteBody)
	}
}

func TestPolicyPlanApply_TokenHandoff(t *testing.T) {
	const planToken = "test-token-abc"
	var gotApplyToken, gotApplyRisk string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/policies/plan":
			w.Write([]byte(`{"plan":{"risk":"high"},"receipt":{"token":"` + planToken + `"}}`))
		case "/api/v1/policies/apply":
			gotApplyToken = r.Header.Get("X-Netra-Plan-Token")
			gotApplyRisk = r.Header.Get("X-Netra-Confirm-Risk")
			w.Write([]byte(`{"applied":true}`))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	c := testClient(t, ts)
	planResult := callTool(t, c, true, "netra_policy_plan", map[string]any{"manifest": "kind: CiliumNetworkPolicy"})
	if planResult.IsError {
		t.Fatalf("plan failed: %+v", planResult)
	}

	applyResult := callTool(t, c, true, "netra_policy_apply", map[string]any{
		"manifest":     "kind: CiliumNetworkPolicy",
		"plan_token":   planToken,
		"confirm_risk": "high",
	})
	if applyResult.IsError {
		t.Fatalf("apply failed: %+v", applyResult)
	}
	if gotApplyToken != planToken {
		t.Fatalf("expected X-Netra-Plan-Token %q, got %q", planToken, gotApplyToken)
	}
	if gotApplyRisk != "high" {
		t.Fatalf("expected X-Netra-Confirm-Risk high, got %q", gotApplyRisk)
	}
}

func TestPolicyApply_RiskMismatchMapsToIsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		w.Write([]byte(`{"error":"preflight risk is high; repeat preflight and apply with X-Netra-Confirm-Risk: high"}`))
	}))
	defer ts.Close()

	c := testClient(t, ts)
	result := callTool(t, c, true, "netra_policy_apply", map[string]any{
		"manifest":   "kind: CiliumNetworkPolicy",
		"plan_token": "sometoken",
	})
	if !result.IsError {
		t.Fatalf("expected isError=true for a 409 response")
	}
	if !strings.Contains(result.Content[0].Text, "409") {
		t.Fatalf("expected status 409 to appear in the result, got %s", result.Content[0].Text)
	}
}

// TestNetPolDefaultDenyPlanSet_BodyMatchesPlan guards against a real bug
// found during implementation: the set tool's handler used to reconstruct
// the request body from typed struct fields, which always included a
// "lease" key (even empty) regardless of whether the caller had passed one
// to plan — producing different bytes than plan hashed, so a real
// preflight token would never actually validate. The fix makes set strip
// only plan_token/confirm_risk from the raw argument map and re-marshal the
// rest, mirroring exactly how the plan tool (a plain endpointTool with
// bodyFields:true) builds its own body. This test calls plan and set with
// no lease argument at all and asserts the server sees byte-identical
// bodies for both.
func TestNetPolDefaultDenyPlanSet_BodyMatchesPlan(t *testing.T) {
	const planToken = "npdd-token"
	var planBody, setBody []byte
	var gotSetToken, gotSetRisk string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		switch r.URL.Path {
		case "/api/v1/ebpf/netpol/default-deny/plan":
			planBody = b
			w.Write([]byte(`{"risk":"medium","matchedWorkloads":1,"receipt":{"token":"` + planToken + `"}}`))
		case "/api/v1/ebpf/netpol/default-deny":
			setBody = b
			gotSetToken = r.Header.Get("X-Netra-Plan-Token")
			gotSetRisk = r.Header.Get("X-Netra-Confirm-Risk")
			w.Write([]byte(`{"netPolDefaultDenies":[{}]}`))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	c := testClient(t, ts)
	selector := map[string]any{"namespace": "payments"}
	planResult := callTool(t, c, true, "netra_ebpf_netpol_default_deny_plan", map[string]any{
		"selector": selector, "enabled": true,
	})
	if planResult.IsError {
		t.Fatalf("plan failed: %+v", planResult)
	}
	setResult := callTool(t, c, true, "netra_ebpf_netpol_default_deny_set", map[string]any{
		"selector": selector, "enabled": true, "plan_token": planToken, "confirm_risk": "medium",
	})
	if setResult.IsError {
		t.Fatalf("set failed: %+v", setResult)
	}
	if gotSetToken != planToken {
		t.Fatalf("expected X-Netra-Plan-Token %q, got %q", planToken, gotSetToken)
	}
	if gotSetRisk != "medium" {
		t.Fatalf("expected X-Netra-Confirm-Risk medium, got %q", gotSetRisk)
	}
	if string(planBody) != string(setBody) {
		t.Fatalf("plan and set bodies must match byte-for-byte (preflight is hash-bound to the body):\nplan: %s\nset:  %s", planBody, setBody)
	}
}

func TestPolicySimulate_SendsRawManifestBodyAndAvailableWithoutMutations(t *testing.T) {
	var gotBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/policies/simulate" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write([]byte(`{"namespace":"prod","name":"eg","governedSources":1,"results":[]}`))
	}))
	defer ts.Close()

	c := testClient(t, ts)
	// allowMutations=false: netra_policy_simulate must still be registered
	// and callable, since it mutates nothing (unlike netra_policy_plan).
	result := callTool(t, c, false, "netra_policy_simulate", map[string]any{"manifest": `{"kind":"CiliumNetworkPolicy"}`})
	if result.IsError {
		t.Fatalf("expected success, got error result: %+v", result)
	}
	if gotBody != `{"kind":"CiliumNetworkPolicy"}` {
		t.Fatalf("expected the raw manifest as the request body, got %q", gotBody)
	}
	if !strings.Contains(result.Content[0].Text, "governedSources") {
		t.Fatalf("unexpected content: %s", result.Content[0].Text)
	}
}

func TestPolicyGitOpsResync_SendsManifestAndConfirmRiskHeader(t *testing.T) {
	var gotBody, gotRisk string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/policies/gitops/resync" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotRisk = r.Header.Get("X-Netra-Confirm-Risk")
		w.Write([]byte(`{"risk":"critical"}`))
	}))
	defer ts.Close()

	c := testClient(t, ts)
	result := callTool(t, c, true, "netra_policy_gitops_resync", map[string]any{
		"manifest":     `{"kind":"CiliumNetworkPolicy"}`,
		"confirm_risk": "critical",
	})
	if result.IsError {
		t.Fatalf("expected success, got error result: %+v", result)
	}
	if gotBody != `{"kind":"CiliumNetworkPolicy"}` {
		t.Fatalf("expected the raw manifest as the request body, got %q", gotBody)
	}
	if gotRisk != "critical" {
		t.Fatalf("expected X-Netra-Confirm-Risk: critical, got %q", gotRisk)
	}
}

func TestPolicyGitOpsResync_GatedBehindMutations(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer ts.Close()
	c := testClient(t, ts)

	withoutMutations, err := buildServer(c, false)
	if err != nil {
		t.Fatalf("buildServer(false): %v", err)
	}
	if names := toolNames(t, withoutMutations); contains(names, "netra_policy_gitops_resync") {
		t.Fatal("expected netra_policy_gitops_resync to be absent when mutations are disabled")
	}

	withMutations, err := buildServer(c, true)
	if err != nil {
		t.Fatalf("buildServer(true): %v", err)
	}
	if names := toolNames(t, withMutations); !contains(names, "netra_policy_gitops_resync") {
		t.Fatal("expected netra_policy_gitops_resync to be present when mutations are enabled")
	}
}

func TestMutationGating(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	c := testClient(t, ts)

	withoutMutations, err := buildServer(c, false)
	if err != nil {
		t.Fatalf("buildServer(false): %v", err)
	}
	if names := toolNames(t, withoutMutations); contains(names, "netra_ebpf_cidr_add") {
		t.Fatalf("expected netra_ebpf_cidr_add to be absent when mutations are disabled")
	}

	withMutations, err := buildServer(c, true)
	if err != nil {
		t.Fatalf("buildServer(true): %v", err)
	}
	if names := toolNames(t, withMutations); !contains(names, "netra_ebpf_cidr_add") {
		t.Fatalf("expected netra_ebpf_cidr_add to be present when mutations are enabled")
	}
}

func toolNames(t *testing.T, srv *mcpserver.Server) []string {
	t.Helper()
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	var resp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("unmarshal tools/list response: %v", err)
	}
	names := make([]string, len(resp.Result.Tools))
	for i, tool := range resp.Result.Tools {
		names[i] = tool.Name
	}
	return names
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
