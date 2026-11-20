// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// rpcLine is a convenience decode target for asserting on response lines.
type rpcLine struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

func serveOne(t *testing.T, srv *Server, requestLine string) rpcLine {
	t.Helper()
	in := strings.NewReader(requestLine + "\n")
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("expected exactly one response line, got %d: %q", len(lines), out.String())
	}
	var got rpcLine
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal response: %v (line: %s)", err, lines[0])
	}
	return got
}

func TestInitializeHandshake(t *testing.T) {
	srv := New("netra-mcp", "0.1.0")
	resp := serveOne(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.ProtocolVersion == "" {
		t.Fatalf("expected non-empty protocolVersion")
	}
	if result.ServerInfo.Name != "netra-mcp" || result.ServerInfo.Version != "0.1.0" {
		t.Fatalf("unexpected serverInfo: %+v", result.ServerInfo)
	}
}

func TestNotificationsInitializedNoResponse(t *testing.T) {
	srv := New("s", "v")
	in := strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no output for a notification, got %q", out.String())
	}
}

func TestToolsListShapeSortedByName(t *testing.T) {
	srv := New("s", "v")
	mustRegister(t, srv, Tool{Name: "zzz_tool", Description: "z", InputSchema: map[string]any{"type": "object"}})
	mustRegister(t, srv, Tool{Name: "aaa_tool", Description: "a"})

	resp := serveOne(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	var result struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if len(result.Tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(result.Tools))
	}
	if result.Tools[0].Name != "aaa_tool" || result.Tools[1].Name != "zzz_tool" {
		t.Fatalf("expected sorted order, got %s then %s", result.Tools[0].Name, result.Tools[1].Name)
	}
	if result.Tools[1].InputSchema == nil {
		t.Fatalf("expected a default schema for a tool with nil InputSchema")
	}
}

func TestToolsCallSuccess(t *testing.T) {
	srv := New("s", "v")
	mustRegister(t, srv, Tool{
		Name: "echo",
		Handler: func(ctx context.Context, args json.RawMessage) (any, bool, error) {
			return map[string]any{"ok": true}, false, nil
		},
	})
	resp := serveOne(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`)
	if resp.Error != nil {
		t.Fatalf("unexpected protocol error: %+v", resp.Error)
	}
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected isError=false")
	}
	if len(result.Content) != 1 || !strings.Contains(result.Content[0].Text, `"ok": true`) {
		t.Fatalf("unexpected content: %+v", result.Content)
	}
}

func TestToolsCallHandlerErrorIsNotAProtocolError(t *testing.T) {
	srv := New("s", "v")
	mustRegister(t, srv, Tool{
		Name: "boom",
		Handler: func(ctx context.Context, args json.RawMessage) (any, bool, error) {
			return nil, false, errors.New("boom")
		},
	})
	resp := serveOne(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"boom","arguments":{}}}`)
	if resp.Error != nil {
		t.Fatalf("expected a normal tool result, not a JSON-RPC error, got %+v", resp.Error)
	}
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected isError=true")
	}
	if !strings.Contains(result.Content[0].Text, "boom") {
		t.Fatalf("expected error text to contain %q, got %q", "boom", result.Content[0].Text)
	}
}

func TestToolsCallIsErrorFlagWithoutGoError(t *testing.T) {
	srv := New("s", "v")
	mustRegister(t, srv, Tool{
		Name: "soft-fail",
		Handler: func(ctx context.Context, args json.RawMessage) (any, bool, error) {
			return map[string]any{"status": 409}, true, nil
		},
	})
	resp := serveOne(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"soft-fail","arguments":{}}}`)
	var result struct {
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected isError=true")
	}
}

func TestUnknownToolIsProtocolError(t *testing.T) {
	srv := New("s", "v")
	resp := serveOne(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}`)
	if resp.Error == nil || resp.Error.Code != codeInvalidParams {
		t.Fatalf("expected invalid-params protocol error, got %+v", resp.Error)
	}
}

func TestUnknownMethodIsProtocolError(t *testing.T) {
	srv := New("s", "v")
	resp := serveOne(t, srv, `{"jsonrpc":"2.0","id":1,"method":"totally/bogus"}`)
	if resp.Error == nil || resp.Error.Code != codeMethodNotFound {
		t.Fatalf("expected method-not-found protocol error, got %+v", resp.Error)
	}
}

func TestMalformedJSONLineRecovers(t *testing.T) {
	srv := New("s", "v")
	in := strings.NewReader("not json at all\n" + `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 response lines (one parse error, one real reply), got %d: %q", len(lines), out.String())
	}
	var first rpcLine
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("unmarshal first line: %v", err)
	}
	if first.Error == nil || first.Error.Code != codeParseError {
		t.Fatalf("expected parse error on first line, got %+v", first.Error)
	}
	var second rpcLine
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("unmarshal second line: %v", err)
	}
	if second.Error != nil {
		t.Fatalf("expected the second, well-formed line to succeed, got %+v", second.Error)
	}
}

func TestDuplicateRegisterErrors(t *testing.T) {
	srv := New("s", "v")
	mustRegister(t, srv, Tool{Name: "dup"})
	if err := srv.Register(Tool{Name: "dup"}); err == nil {
		t.Fatalf("expected error registering a duplicate tool name")
	}
}

func mustRegister(t *testing.T, srv *Server, tool Tool) {
	t.Helper()
	if err := srv.Register(tool); err != nil {
		t.Fatalf("register %s: %v", tool.Name, err)
	}
}

func TestPromptsListAndGet(t *testing.T) {
	srv := New("s", "v")
	if err := srv.RegisterPrompt(Prompt{
		Name:        "netra_triage",
		Description: "triage",
		Arguments:   []PromptArg{{Name: "namespace", Description: "ns", Required: false}},
		Messages:    []PromptMessage{{Role: "user", Text: "Look at {{namespace}}"}},
	}); err != nil {
		t.Fatalf("register prompt: %v", err)
	}
	list := serveOne(t, srv, `{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`)
	if list.Error != nil {
		t.Fatalf("list error: %+v", list.Error)
	}
	var listed struct {
		Prompts []struct {
			Name string `json:"name"`
		} `json:"prompts"`
	}
	if err := json.Unmarshal(list.Result, &listed); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(listed.Prompts) != 1 || listed.Prompts[0].Name != "netra_triage" {
		t.Fatalf("prompts=%+v", listed.Prompts)
	}
	got := serveOne(t, srv, `{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"netra_triage","arguments":{"namespace":"prod"}}}`)
	if got.Error != nil {
		t.Fatalf("get error: %+v", got.Error)
	}
	if !strings.Contains(string(got.Result), "prod") {
		t.Fatalf("expected substitution, got %s", got.Result)
	}
}

func TestResourcesListAndRead(t *testing.T) {
	srv := New("s", "v")
	if err := srv.RegisterResource(Resource{
		URI:      "netra://ai/brief",
		Name:     "brief",
		MimeType: "application/json",
		Read:     func(context.Context) (string, error) { return `{"ok":true}`, nil },
	}); err != nil {
		t.Fatalf("register resource: %v", err)
	}
	list := serveOne(t, srv, `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)
	if list.Error != nil {
		t.Fatalf("list error: %+v", list.Error)
	}
	if !strings.Contains(string(list.Result), "netra://ai/brief") {
		t.Fatalf("list=%s", list.Result)
	}
	got := serveOne(t, srv, `{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"netra://ai/brief"}}`)
	if got.Error != nil {
		t.Fatalf("read error: %+v", got.Error)
	}
	// got.Result is the raw JSON-RPC result; the resource's own JSON body
	// lives inside its "text" string field, so its quotes are escaped here.
	if !strings.Contains(string(got.Result), `\"ok\":true`) {
		t.Fatalf("read=%s", got.Result)
	}
}
