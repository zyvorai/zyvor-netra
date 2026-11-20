// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package chatops

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func postSigned(t *testing.T, h http.Handler, secret string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	body := form.Encode()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := sign(secret, ts, []byte(body))
	r := httptest.NewRequest("POST", "/chatops/slack", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Slack-Request-Timestamp", ts)
	r.Header.Set("X-Slack-Signature", sig)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestHandlerRejectsBadSignature(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not reach the controller with a bad signature")
	})
	h := NewHandler(Config{SigningSecret: "shh", AllowMutations: true, Client: c})
	form := url.Values{"command": {"/netra"}, "text": {"status"}}
	body := form.Encode()
	r := httptest.NewRequest("POST", "/chatops/slack", strings.NewReader(body))
	r.Header.Set("X-Slack-Request-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	r.Header.Set("X-Slack-Signature", "v0=wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
}

func TestHandlerSlashCommandStatus(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"version":"0.27.45"}`)) })
	h := NewHandler(Config{SigningSecret: "shh", AllowMutations: true, Client: c})
	rec := postSigned(t, h, "shh", url.Values{"command": {"/netra"}, "text": {"status"}})
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var msg struct{ Text string }
	if err := json.Unmarshal(rec.Body.Bytes(), &msg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Text, "0.27.45") {
		t.Fatalf("text=%q", msg.Text)
	}
}

func TestHandlerModeReturnsConfirmationBlocksNotExecution(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("must not execute before confirmation") })
	h := NewHandler(Config{SigningSecret: "shh", AllowMutations: true, Client: c})
	rec := postSigned(t, h, "shh", url.Values{"command": {"/netra"}, "text": {"mode enforce"}})
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var msg struct {
		Blocks []map[string]any `json:"blocks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &msg); err != nil {
		t.Fatal(err)
	}
	if len(msg.Blocks) == 0 {
		t.Fatalf("expected confirmation blocks, got %s", rec.Body.String())
	}
}

func TestHandlerInteractionExecutesAndTagsActor(t *testing.T) {
	var gotActor, gotPath, gotBody string
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotActor = r.Header.Get("X-Netra-Actor")
		gotPath = r.URL.Path + "?" + r.URL.RawQuery
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write([]byte(`{"mode":"enforce"}`))
	})
	h := NewHandler(Config{SigningSecret: "shh", AllowMutations: true, Client: c})

	p := pendingAction{Method: "PUT", Path: "/api/v1/ebpf/mode?lease=15m", Body: `{"mode":"enforce"}`, Summary: "switch to enforce"}
	payload := `{"type":"block_actions","user":{"id":"U123","username":"alice"},"actions":[{"action_id":"` + pendingActionID + `","value":"` + encodePending(p) + `"}]}`
	rec := postSigned(t, h, "shh", url.Values{"payload": {payload}})
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if gotActor != "chatops:U123" {
		t.Fatalf("actor=%q, want chatops:U123", gotActor)
	}
	if gotPath != "/api/v1/ebpf/mode?lease=15m" {
		t.Fatalf("path=%q", gotPath)
	}
	if !strings.Contains(gotBody, "enforce") {
		t.Fatalf("body=%q", gotBody)
	}
	var msg struct{ Text string }
	if err := json.Unmarshal(rec.Body.Bytes(), &msg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Text, "U123") {
		t.Fatalf("reply text=%q, want it to name the confirming user", msg.Text)
	}
}

func TestHandlerInteractionRejectsWrongActionID(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not call the controller for an unrecognized action")
	})
	h := NewHandler(Config{SigningSecret: "shh", AllowMutations: true, Client: c})
	payload := `{"type":"block_actions","user":{"id":"U123"},"actions":[{"action_id":"something_else","value":"x"}]}`
	rec := postSigned(t, h, "shh", url.Values{"payload": {payload}})
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	var msg struct{ Text string }
	_ = json.Unmarshal(rec.Body.Bytes(), &msg)
	if !strings.Contains(msg.Text, "Unrecognized") {
		t.Fatalf("text=%q", msg.Text)
	}
}

func TestHandlerAskSendsStableConversationIDPerChannelAndUser(t *testing.T) {
	var gotConversationIDs []string
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ai/agent" {
			w.Write([]byte(`{}`))
			return
		}
		var req struct {
			ConversationID string `json:"conversationId"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		gotConversationIDs = append(gotConversationIDs, req.ConversationID)
		w.Write([]byte(`{"headline":"ok","severity":"info","summary":"ok","engine":"heuristic"}`))
	})
	h := NewHandler(Config{SigningSecret: "shh", AllowMutations: true, Client: c})

	postSigned(t, h, "shh", url.Values{"command": {"/netra"}, "text": {"ask one"}, "channel_id": {"C1"}, "user_id": {"U1"}})
	postSigned(t, h, "shh", url.Values{"command": {"/netra"}, "text": {"ask two"}, "channel_id": {"C1"}, "user_id": {"U1"}})
	postSigned(t, h, "shh", url.Values{"command": {"/netra"}, "text": {"ask three"}, "channel_id": {"C1"}, "user_id": {"U2"}})

	if len(gotConversationIDs) != 3 {
		t.Fatalf("got %d ask calls, want 3", len(gotConversationIDs))
	}
	if gotConversationIDs[0] == "" || gotConversationIDs[0] != gotConversationIDs[1] {
		t.Fatalf("same channel+user should reuse one conversation id, got %q then %q", gotConversationIDs[0], gotConversationIDs[1])
	}
	if gotConversationIDs[2] == "" || gotConversationIDs[2] == gotConversationIDs[0] {
		t.Fatalf("a different user in the same channel must get a distinct conversation id, got %q vs %q", gotConversationIDs[2], gotConversationIDs[0])
	}
}

func TestNewHandlerPanicsWithoutSigningSecret(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected NewHandler to panic with an empty SigningSecret")
		}
	}()
	NewHandler(Config{Client: NewClient("http://example", "k")})
}
