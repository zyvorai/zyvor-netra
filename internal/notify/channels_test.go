// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/zyvorai/netra/internal/webhook"
)

func TestDispatcherFanOutAndMinSeverity(t *testing.T) {
	var nCritical, nAll atomic.Int32
	srvCrit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nCritical.Add(1)
	}))
	defer srvCrit.Close()
	srvAll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nAll.Add(1)
	}))
	defer srvAll.Close()

	crit, err := NewWebhookChannel(webhook.Config{Name: "crit", URL: srvCrit.URL, MinSeverity: "critical", MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	all, err := NewWebhookChannel(webhook.Config{Name: "all", URL: srvAll.URL, MinSeverity: "info", MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(32)
	d.Add(crit)
	d.Add(all)
	d.Start(2)
	defer d.Stop()

	if !d.Publish(Event{Severity: "warning", Kind: "k"}) {
		t.Fatal("publish rejected")
	}
	waitHits(t, &nAll, 1)
	if nCritical.Load() != 0 {
		t.Fatalf("critical sink should skip warning, got %d", nCritical.Load())
	}

	if !d.Publish(Event{Severity: "critical", Kind: "k2"}) {
		t.Fatal("publish rejected")
	}
	waitHits(t, &nCritical, 1)
	waitHits(t, &nAll, 2)
}

func waitHits(t *testing.T, n *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if n.Load() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("wanted >= %d hits, got %d", want, n.Load())
}

func TestSlackIncomingPostsBlockKit(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ch, err := NewSlackChannel(SlackConfig{
		base: base{name: "sl", minSeverity: "info", timeout: time.Second, maxAttempts: 1},
		Mode: "incoming",
		URL:  srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Send(context.Background(), Event{Severity: "warning", Kind: "k", Subject: "s", Message: "hi"}); err != nil {
		t.Fatal(err)
	}
	if body["text"] == nil || body["blocks"] == nil {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func TestSlackAPIValidation(t *testing.T) {
	_, err := NewSlackChannel(SlackConfig{base: base{name: "sl"}, Mode: "api", Token: "xoxb-t"})
	if err == nil {
		t.Fatal("expected channel required")
	}
	_, err = NewSlackChannel(SlackConfig{
		base:    base{name: "sl", timeout: time.Second, maxAttempts: 1},
		Mode:    "api",
		Token:   "xoxb-t",
		Channel: "#ops",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTeamsAdaptiveCard(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}))
	defer srv.Close()
	ch, err := NewTeamsChannel(TeamsConfig{
		base: base{name: "tm", minSeverity: "info", timeout: time.Second, maxAttempts: 1},
		URL:  srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Send(context.Background(), Event{Severity: "critical", Kind: "k", Message: "m"}); err != nil {
		t.Fatal(err)
	}
	atts, ok := body["attachments"].([]any)
	if !ok || len(atts) == 0 {
		t.Fatalf("missing attachments: %+v", body)
	}
}

func TestTwilioSMSAndWhatsApp(t *testing.T) {
	var mu sync.Mutex
	var posts []url.Values
	var users []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _, _ := r.BasicAuth()
		_ = r.ParseForm()
		mu.Lock()
		users = append(users, u)
		posts = append(posts, r.PostForm)
		mu.Unlock()
		w.WriteHeader(201)
	}))
	defer srv.Close()

	ch, err := NewTwilioChannel(TwilioConfig{
		base:       base{name: "sms", minSeverity: "info", timeout: time.Second, maxAttempts: 1},
		Kind:       TwilioSMS,
		AccountSID: "ACtest",
		AuthToken:  "secret",
		From:       "+1000",
		To:         []string{"+2000"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tc := ch.(*twilioChannel)
	tc.apiBase = srv.URL
	tc.client = srv.Client()
	if err := tc.Send(context.Background(), Event{Severity: "critical", Kind: "k", Message: "alert"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(posts) != 1 || posts[0].Get("From") != "+1000" || posts[0].Get("To") != "+2000" {
		t.Fatalf("sms form: %+v", posts)
	}
	if users[0] != "ACtest" {
		t.Fatalf("auth user %q", users[0])
	}
	mu.Unlock()

	wa, err := NewTwilioChannel(TwilioConfig{
		base:       base{name: "wa", minSeverity: "info", timeout: time.Second, maxAttempts: 1},
		Kind:       TwilioWhatsApp,
		AccountSID: "ACtest",
		AuthToken:  "secret",
		From:       "+1000",
		To:         []string{"+2000"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wac := wa.(*twilioChannel)
	wac.apiBase = srv.URL
	wac.client = srv.Client()
	if err := wac.Send(context.Background(), Event{Severity: "critical", Kind: "k", Message: "wa"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	last := posts[len(posts)-1]
	if last.Get("From") != "whatsapp:+1000" || last.Get("To") != "whatsapp:+2000" {
		t.Fatalf("whatsapp form: %+v", last)
	}
}

func TestHTTPBridgeEnvelopeAndHMAC(t *testing.T) {
	const secret = "s3cret"
	var gotSig string
	var env BridgeEnvelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Netra-Signature")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &env)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(raw)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if gotSig != want {
			t.Errorf("sig got %s want %s", gotSig, want)
		}
	}))
	defer srv.Close()

	ch, err := NewHTTPBridgeChannel(HTTPBridgeConfig{
		base:        base{name: "br", minSeverity: "info", timeout: time.Second, maxAttempts: 1},
		URL:         srv.URL,
		Secret:      secret,
		ChannelHint: "sms",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev := Event{Severity: "warning", Kind: "k", Subject: "s", Message: "m"}
	if err := ch.Send(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if env.ChannelHint != "sms" || env.Event.Kind != "k" {
		t.Fatalf("envelope: %+v", env)
	}
}

func TestEmailChannelInjectedSender(t *testing.T) {
	var gotSubj, gotBody string
	ch, err := NewEmailChannel(EmailConfig{
		base:     base{name: "mail", minSeverity: "warning", timeout: time.Second, maxAttempts: 1},
		SMTPHost: "smtp.example:587",
		From:     "netra@example.com",
		To:       []string{"ops@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ec := ch.(*emailChannel)
	ec.send = func(ctx context.Context, cfg EmailConfig, subject, body string) error {
		gotSubj, gotBody = subject, body
		return nil
	}
	if err := ec.Send(context.Background(), Event{Severity: "info", Kind: "k"}); err != nil {
		t.Fatal(err)
	}
	if gotSubj != "" {
		t.Fatal("info should be filtered by minSeverity=warning")
	}
	if err := ec.Send(context.Background(), Event{Severity: "critical", Kind: "drop", Subject: "n1", Message: "spike"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotSubj, "CRITICAL") || !strings.Contains(gotBody, "spike") {
		t.Fatalf("subj=%q body=%q", gotSubj, gotBody)
	}
}

func TestSMSBodyKeepsValidUTF8(t *testing.T) {
	ev := Event{Severity: "high", Kind: "k", Subject: "s", Message: strings.Repeat("é", 2000)}
	got := SMSBody(ev)
	if !utf8.ValidString(got) || len(got) > 1500 {
		t.Fatalf("invalid or too long: valid=%v len=%d", utf8.ValidString(got), len(got))
	}
}
