// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package chatops

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeControllerClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "test-key")
}

func TestDispatchHelp(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("help must not call the controller") })
	reply, pending := Dispatch(context.Background(), c, true, "", "")
	if pending != nil || !strings.Contains(reply, "Netra ChatOps") {
		t.Fatalf("reply=%q pending=%v", reply, pending)
	}
}

func TestDispatchStatusCallsThrough(t *testing.T) {
	var gotPath, gotAuth string
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{"version":"0.27.45"}`))
	})
	reply, pending := Dispatch(context.Background(), c, true, "status", "")
	if pending != nil {
		t.Fatalf("status must not require confirmation, got pending=%v", pending)
	}
	if gotPath != "/api/v1/status" {
		t.Fatalf("path=%q", gotPath)
	}
	if gotAuth != "Bearer test-key" {
		t.Fatalf("auth=%q", gotAuth)
	}
	if !strings.Contains(reply, "0.27.45") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestDispatchUnknownCommand(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("unknown command must not call the controller") })
	reply, pending := Dispatch(context.Background(), c, true, "frobnicate", "")
	if pending != nil || !strings.Contains(reply, "Unknown command") {
		t.Fatalf("reply=%q pending=%v", reply, pending)
	}
}

func TestDispatchModeDisabledWithoutMutations(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not call the controller when mutations are disabled")
	})
	reply, pending := Dispatch(context.Background(), c, false, "mode enforce", "")
	if pending != nil || !strings.Contains(reply, "disabled") {
		t.Fatalf("reply=%q pending=%v", reply, pending)
	}
}

func TestDispatchModeRequiresConfirmationNotImmediateExecution(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("mode must never call the controller before confirmation")
	})
	reply, pending := Dispatch(context.Background(), c, true, "mode enforce 30m", "")
	if pending == nil {
		t.Fatal("expected a pending confirmation, not immediate execution")
	}
	if pending.Method != "PUT" || pending.Path != "/api/v1/ebpf/mode?lease=30m" {
		t.Fatalf("pending=%#v", pending)
	}
	if !strings.Contains(pending.Body, `"mode":"enforce"`) {
		t.Fatalf("body=%q", pending.Body)
	}
	if !strings.Contains(reply, "Confirm") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestDispatchModeRejectsInvalidMode(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not call the controller for an invalid mode")
	})
	reply, pending := Dispatch(context.Background(), c, true, "mode sideways", "")
	if pending != nil || !strings.Contains(reply, "observe") {
		t.Fatalf("reply=%q pending=%v", reply, pending)
	}
}

func TestDispatchCaptureDisabledWithoutMutations(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not call the controller when mutations are disabled")
	})
	reply, pending := Dispatch(context.Background(), c, false, "capture start node-1 protocol=tcp", "")
	if pending != nil || !strings.Contains(reply, "disabled") {
		t.Fatalf("reply=%q pending=%v", reply, pending)
	}
}

func TestDispatchCaptureStartRequiresConfirmationNotImmediateExecution(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("capture must never call the controller before confirmation")
	})
	reply, pending := Dispatch(context.Background(), c, true, "capture start node-1 protocol=tcp port=443 duration=30s", "")
	if pending == nil {
		t.Fatal("expected a pending confirmation, not immediate execution")
	}
	if pending.Method != "PUT" || pending.Path != "/api/v1/vms/node-1/capture" {
		t.Fatalf("pending=%#v", pending)
	}
	if !strings.Contains(pending.Body, `"protocol":"tcp"`) || !strings.Contains(pending.Body, `"port":443`) || !strings.Contains(pending.Body, `"durationSeconds":30`) {
		t.Fatalf("body=%q", pending.Body)
	}
	if !strings.Contains(reply, "Confirm") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestDispatchCaptureStartRejectsUnfiltered(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not call the controller for an unfiltered capture request")
	})
	reply, pending := Dispatch(context.Background(), c, true, "capture start node-1", "")
	if pending != nil || !strings.Contains(reply, "required") {
		t.Fatalf("reply=%q pending=%v", reply, pending)
	}
}

func TestDispatchCaptureStopRequiresConfirmation(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("capture stop must never call the controller before confirmation")
	})
	reply, pending := Dispatch(context.Background(), c, true, "capture stop node-1", "")
	if pending == nil {
		t.Fatal("expected a pending confirmation, not immediate execution")
	}
	if pending.Method != "DELETE" || pending.Path != "/api/v1/vms/node-1/capture" {
		t.Fatalf("pending=%#v", pending)
	}
	if !strings.Contains(reply, "Confirm") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestEncodeDecodePendingRoundTrip(t *testing.T) {
	p := pendingAction{Method: "PUT", Path: "/api/v1/ebpf/mode?lease=15m", Body: `{"mode":"enforce"}`, Summary: "switch to enforce"}
	got, err := decodePending(encodePending(p))
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Fatalf("got=%#v want=%#v", got, p)
	}
}

func TestDecodePendingRejectsMalformed(t *testing.T) {
	if _, err := decodePending("not|enough|parts"); err == nil {
		t.Fatal("expected an error for a malformed pending value")
	}
	if _, err := decodePending("PUT|/x|not-base64!!|summary"); err == nil {
		t.Fatal("expected an error for a non-base64 body segment")
	}
}

func TestDispatchAskCallsThroughAndNeverConfirms(t *testing.T) {
	var gotPath, gotMethod, gotAuth, gotBody string
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write([]byte(`{"headline":"All clear","severity":"info","summary":"No anomalies in the last 5m.","findings":[{"kind":"drops","subject":"checkout-service","message":"3 policy drops, reason=cidr"}],"nextSteps":["Review the CIDR rule if this is unexpected."],"engine":"heuristic"}`))
	})
	// ask must never require confirmation, unlike mode — it's read-only,
	// so this is checked even with allowMutations=false.
	reply, pending := Dispatch(context.Background(), c, false, "ask why is checkout-service flaky", "")
	if pending != nil {
		t.Fatalf("ask must not require confirmation, got pending=%v", pending)
	}
	if gotMethod != "POST" || gotPath != "/api/v1/ai/agent" {
		t.Fatalf("method=%q path=%q", gotMethod, gotPath)
	}
	if gotAuth != "Bearer test-key" {
		t.Fatalf("auth=%q", gotAuth)
	}
	if !strings.Contains(gotBody, "why is checkout-service flaky") {
		t.Fatalf("request body=%q missing the question", gotBody)
	}
	if strings.Contains(gotBody, "conversationId") {
		t.Fatalf("request body=%q should omit conversationId when Dispatch was given no conversation key", gotBody)
	}
	for _, want := range []string{"All clear", "info", "No anomalies in the last 5m.", "checkout-service", "3 policy drops", "Review the CIDR rule", "heuristic"} {
		if !strings.Contains(reply, want) {
			t.Fatalf("reply=%q missing %q", reply, want)
		}
	}
}

func TestDispatchAskWithConversationKeySendsConversationID(t *testing.T) {
	var gotBody string
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write([]byte(`{"headline":"All clear","severity":"info","summary":"ok","engine":"heuristic","conversationId":"slack:C1:U1"}`))
	})
	reply, pending := Dispatch(context.Background(), c, true, "ask what about that", "slack:C1:U1")
	if pending != nil {
		t.Fatalf("ask must not require confirmation, got pending=%v", pending)
	}
	if !strings.Contains(gotBody, `"conversationId":"slack:C1:U1"`) {
		t.Fatalf("request body=%q missing conversationId", gotBody)
	}
	if !strings.Contains(reply, "All clear") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestDispatchAskWithNoQuestionStillCallsThrough(t *testing.T) {
	var gotBody string
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write([]byte(`{"headline":"Cluster brief","severity":"warning","summary":"1 warning finding.","engine":"heuristic"}`))
	})
	reply, pending := Dispatch(context.Background(), c, true, "ask", "")
	if pending != nil {
		t.Fatalf("ask must not require confirmation, got pending=%v", pending)
	}
	if !strings.Contains(gotBody, `"question":""`) {
		t.Fatalf("expected an empty-question request body, got %q", gotBody)
	}
	if !strings.Contains(reply, "Cluster brief") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestDispatchForgetWithNoConversationKeyDoesNotCallThrough(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("forget with no conversation key must not call the controller")
	})
	reply, pending := Dispatch(context.Background(), c, true, "forget", "")
	if pending != nil {
		t.Fatalf("forget must not require confirmation, got pending=%v", pending)
	}
	if !strings.Contains(reply, "Nothing to forget") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestDispatchForgetCallsThrough(t *testing.T) {
	var gotPath, gotMethod, gotBody string
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write([]byte(`{"ok":true}`))
	})
	reply, pending := Dispatch(context.Background(), c, true, "forget", "slack:C1:U1")
	if pending != nil {
		t.Fatalf("forget must not require confirmation, got pending=%v", pending)
	}
	if gotMethod != "POST" || gotPath != "/api/v1/ai/forget" {
		t.Fatalf("method=%q path=%q", gotMethod, gotPath)
	}
	if !strings.Contains(gotBody, `"conversationId":"slack:C1:U1"`) {
		t.Fatalf("request body=%q missing conversationId", gotBody)
	}
	if !strings.Contains(reply, "Cleared") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestDispatchForgetRendersErrorOnNon2xx(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	reply, pending := Dispatch(context.Background(), c, true, "forget", "slack:C1:U1")
	if pending != nil {
		t.Fatalf("forget must not require confirmation, got pending=%v", pending)
	}
	if !strings.Contains(reply, "HTTP 503") {
		t.Fatalf("reply=%q", reply)
	}
}

func TestDispatchAskRendersErrorOnNon2xx(t *testing.T) {
	c := fakeControllerClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"controller store is not initialised"}`))
	})
	reply, pending := Dispatch(context.Background(), c, true, "ask anything", "")
	if pending != nil {
		t.Fatalf("ask must not require confirmation, got pending=%v", pending)
	}
	if !strings.Contains(reply, "HTTP 503") || !strings.Contains(reply, "controller store is not initialised") {
		t.Fatalf("reply=%q", reply)
	}
}
