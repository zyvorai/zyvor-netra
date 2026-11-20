// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package chatops

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func activityWithMentionEntity(botID, mentionText, text string) teamsActivity {
	a := teamsActivity{Type: "message", Text: text}
	a.Recipient.ID = botID
	a.Entities = append(a.Entities, struct {
		Type      string `json:"type"`
		Text      string `json:"text"`
		Mentioned struct {
			ID string `json:"id"`
		} `json:"mentioned"`
	}{Type: "mention", Text: mentionText})
	a.Entities[0].Mentioned.ID = botID
	return a
}

func TestStripTeamsMentionWithEntities(t *testing.T) {
	a := activityWithMentionEntity("bot-1", "<at>Netra</at>", "<at>Netra</at> status")
	if got := stripTeamsMention(a); got != "status" {
		t.Fatalf("got %q, want %q", got, "status")
	}
}

func TestStripTeamsMentionIgnoresMentionOfSomeoneElse(t *testing.T) {
	a := activityWithMentionEntity("bot-1", "<at>Alice</at>", "<at>Alice</at> status")
	a.Entities[0].Mentioned.ID = "someone-else"
	if got := stripTeamsMention(a); got != "<at>Alice</at> status" {
		t.Fatalf("expected a mention of a different recipient to be left alone, got %q", got)
	}
}

func TestStripTeamsMentionFallbackWithoutEntities(t *testing.T) {
	a := teamsActivity{Type: "message", Text: "<at>Netra</at> status"}
	if got := stripTeamsMention(a); got != "status" {
		t.Fatalf("got %q, want %q", got, "status")
	}
}

func TestStripTeamsMentionNoMention(t *testing.T) {
	a := teamsActivity{Type: "message", Text: "/netra status"}
	if got := stripTeamsMention(a); got != "/netra status" {
		t.Fatalf("got %q, want unchanged text", got)
	}
}

func TestDispatchTeamsActivityStatus(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"version":"0.27.47"}`)) })
	cfg := TeamsConfig{AppID: "app-1", AllowMutations: true, Client: c}
	a := teamsActivity{Type: "message", Text: "/netra status"}
	reply := dispatchTeamsActivity(context.Background(), cfg, a)
	if !strings.Contains(reply, "0.27.47") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestDispatchTeamsActivityModeReturnsConfirmToken(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("must not execute before confirmation") })
	cfg := TeamsConfig{AppID: "app-1", AllowMutations: true, Client: c}
	a := teamsActivity{Type: "message", Text: "/netra mode enforce"}
	reply := dispatchTeamsActivity(context.Background(), cfg, a)
	if !strings.Contains(reply, teamsConfirmPrefix) {
		t.Fatalf("expected reply to include the confirm instruction, got %q", reply)
	}
}

func TestDispatchTeamsActivitySendsStableConversationIDPerConversationAndUser(t *testing.T) {
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
	cfg := TeamsConfig{AppID: "app-1", AllowMutations: true, Client: c}

	a1 := teamsActivity{Type: "message", Text: "/netra ask one"}
	a1.Conversation.ID = "conv-1"
	a1.From.ID = "user-1"
	dispatchTeamsActivity(context.Background(), cfg, a1)

	a2 := teamsActivity{Type: "message", Text: "/netra ask two"}
	a2.Conversation.ID = "conv-1"
	a2.From.ID = "user-1"
	dispatchTeamsActivity(context.Background(), cfg, a2)

	a3 := teamsActivity{Type: "message", Text: "/netra ask three"}
	a3.Conversation.ID = "conv-1"
	a3.From.ID = "user-2"
	dispatchTeamsActivity(context.Background(), cfg, a3)

	if len(gotConversationIDs) != 3 {
		t.Fatalf("got %d ask calls, want 3", len(gotConversationIDs))
	}
	if gotConversationIDs[0] == "" || gotConversationIDs[0] != gotConversationIDs[1] {
		t.Fatalf("same conversation+user should reuse one conversation id, got %q then %q", gotConversationIDs[0], gotConversationIDs[1])
	}
	if gotConversationIDs[2] == "" || gotConversationIDs[2] == gotConversationIDs[0] {
		t.Fatalf("a different user in the same Teams conversation must get a distinct conversation id, got %q vs %q", gotConversationIDs[2], gotConversationIDs[0])
	}
}

func TestDispatchTeamsActivityStripsMentionBeforeDispatch(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ok":true}`)) })
	cfg := TeamsConfig{AppID: "app-1", AllowMutations: true, Client: c}
	a := activityWithMentionEntity("bot-1", "<at>Netra</at>", "<at>Netra</at> /netra status")
	reply := dispatchTeamsActivity(context.Background(), cfg, a)
	if strings.Contains(reply, "Unknown command") {
		t.Fatalf("expected the mention to be stripped before dispatch, got %q", reply)
	}
}

func TestConfirmTeamsPendingExecutesAndTagsActor(t *testing.T) {
	var gotActor, gotBody string
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotActor = r.Header.Get("X-Netra-Actor")
		b := new(bytes.Buffer)
		b.ReadFrom(r.Body)
		gotBody = b.String()
		w.Write([]byte(`{"mode":"enforce"}`))
	})
	p := pendingAction{Method: "PUT", Path: "/api/v1/ebpf/mode?lease=15m", Body: `{"mode":"enforce"}`, Summary: "switch to enforce"}
	reply := confirmTeamsPending(context.Background(), c, encodePending(p), "teams-user-1")
	if gotActor != "chatops-teams:teams-user-1" {
		t.Fatalf("actor=%q, want chatops-teams:teams-user-1", gotActor)
	}
	if !strings.Contains(gotBody, "enforce") {
		t.Fatalf("body=%q", gotBody)
	}
	if !strings.Contains(reply, "teams-user-1") {
		t.Fatalf("reply should name the confirming user, got %q", reply)
	}
}

func TestConfirmTeamsPendingMalformedToken(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not call the controller for a malformed token")
	})
	reply := confirmTeamsPending(context.Background(), c, "not-a-valid-token", "teams-user-1")
	if !strings.Contains(reply, "expired or is malformed") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestConfirmTeamsPendingMissingFromID(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not call the controller with no confirming user")
	})
	p := pendingAction{Method: "PUT", Path: "/api/v1/ebpf/mode", Body: `{"mode":"observe"}`, Summary: "switch to observe"}
	reply := confirmTeamsPending(context.Background(), c, encodePending(p), "")
	if !strings.Contains(reply, "Could not identify") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestNewTeamsHandlerPanicsWithoutAppID(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected NewTeamsHandler to panic with an empty AppID")
		}
	}()
	NewTeamsHandler(TeamsConfig{Client: NewClient("http://example", "k")})
}

func TestTeamsHandlerRejectsMissingBearerToken(t *testing.T) {
	f := newTeamsTestFixture(t)
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("must not reach the controller with no token") })
	h := NewTeamsHandler(TeamsConfig{AppID: "app-1", AllowMutations: true, Client: c, Verifier: f.verifier("app-1")})
	r := httptest.NewRequest("POST", "/chatops/teams", strings.NewReader(`{"type":"message","text":"status"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
}

func TestTeamsHandlerRejectsInvalidToken(t *testing.T) {
	f := newTeamsTestFixture(t)
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not reach the controller with an invalid token")
	})
	h := NewTeamsHandler(TeamsConfig{AppID: "app-1", AllowMutations: true, Client: c, Verifier: f.verifier("app-1")})
	r := httptest.NewRequest("POST", "/chatops/teams", strings.NewReader(`{"type":"message","text":"status"}`))
	r.Header.Set("Authorization", "Bearer not-a-real-jwt")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
}

func TestTeamsHandlerIgnoresNonMessageActivity(t *testing.T) {
	f := newTeamsTestFixture(t)
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not reach the controller for a non-message activity")
	})
	h := NewTeamsHandler(TeamsConfig{AppID: "app-1", AllowMutations: true, Client: c, Verifier: f.verifier("app-1")})
	tok := signTestJWT(t, f.priv, f.kid, validTeamsClaims("app-1"))
	r := httptest.NewRequest("POST", "/chatops/teams", strings.NewReader(`{"type":"conversationUpdate"}`))
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
}

func TestTeamsHandlerEndToEndSlashCommand(t *testing.T) {
	f := newTeamsTestFixture(t)
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"version":"0.27.47"}`)) })
	h := NewTeamsHandler(TeamsConfig{AppID: "app-1", AllowMutations: true, Client: c, Verifier: f.verifier("app-1")})
	tok := signTestJWT(t, f.priv, f.kid, validTeamsClaims("app-1"))

	body, _ := json.Marshal(teamsActivity{Type: "message", Text: "/netra status"})
	r := httptest.NewRequest("POST", "/chatops/teams", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var reply struct{ Text string }
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply.Text, "0.27.47") {
		t.Fatalf("text=%q", reply.Text)
	}
}

func TestTeamsHandlerEndToEndConfirmFlow(t *testing.T) {
	f := newTeamsTestFixture(t)
	var gotActor string
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotActor = r.Header.Get("X-Netra-Actor")
		w.Write([]byte(`{"mode":"enforce"}`))
	})
	h := NewTeamsHandler(TeamsConfig{AppID: "app-1", AllowMutations: true, Client: c, Verifier: f.verifier("app-1")})
	tok := signTestJWT(t, f.priv, f.kid, validTeamsClaims("app-1"))

	modeBody, _ := json.Marshal(teamsActivity{Type: "message", Text: "/netra mode enforce"})
	r := httptest.NewRequest("POST", "/chatops/teams", bytes.NewReader(modeBody))
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var first struct{ Text string }
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	idx := strings.Index(first.Text, teamsConfirmPrefix)
	if idx < 0 {
		t.Fatalf("expected a confirm instruction, got %q", first.Text)
	}
	rest := first.Text[idx:]
	end := strings.Index(rest, "`") // reply wraps the command in backticks; stop before the closing one
	if end < 0 {
		end = len(rest)
	}
	confirmCommand := rest[:end]

	from := teamsActivity{Type: "message", Text: confirmCommand}
	from.From.ID = "teams-user-9"
	confirmBody, _ := json.Marshal(from)
	r2 := httptest.NewRequest("POST", "/chatops/teams", bytes.NewReader(confirmBody))
	r2.Header.Set("Authorization", "Bearer "+tok)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, r2)
	if rec2.Code != 200 {
		t.Fatalf("status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	if gotActor != "chatops-teams:teams-user-9" {
		t.Fatalf("actor=%q, want chatops-teams:teams-user-9", gotActor)
	}
	var second struct{ Text string }
	if err := json.Unmarshal(rec2.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(second.Text, "teams-user-9") {
		t.Fatalf("text=%q", second.Text)
	}
}
