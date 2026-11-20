// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSendSignsBody(t *testing.T) {
	var gotSig string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Netra-Signature")
		gotBody, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	s, err := New(Config{Name: "t", URL: srv.URL, Secret: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), Event{Kind: "k", Severity: "warning", Subject: "s"}); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte("hunter2"))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("sig mismatch\n got %q\nwant %q", gotSig, want)
	}
}

func TestSendRespectsMinSeverity(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	s, _ := New(Config{Name: "t", URL: srv.URL, MinSeverity: "critical"})
	if err := s.Send(context.Background(), Event{Severity: "info"}); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("expected 0 requests, got %d", got)
	}
}

func TestSendPropagatesNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	s, _ := New(Config{Name: "t", URL: srv.URL})
	if err := s.Send(context.Background(), Event{Severity: "info"}); err == nil {
		t.Fatal("want error, got nil")
	}
}

func TestSendAddsCustomHeaders(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Tenant")
	}))
	defer srv.Close()

	s, _ := New(Config{Name: "t", URL: srv.URL, Headers: map[string]string{"X-Tenant": "acme"}})
	if err := s.Send(context.Background(), Event{Severity: "info"}); err != nil {
		t.Fatal(err)
	}
	if got != "acme" {
		t.Fatalf("got %q", got)
	}
}

func TestNewRejectsMissingFields(t *testing.T) {
	if _, err := New(Config{URL: "http://x"}); err == nil {
		t.Fatal("want error for missing Name")
	}
	if _, err := New(Config{Name: "t"}); err == nil {
		t.Fatal("want error for missing URL")
	}
}

func TestSeverityGE(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"critical", "warning", true},
		{"warning", "critical", false},
		{"info", "info", true},
		{"bogus", "info", false},
	}
	for _, c := range cases {
		if got := severityGE(c.a, c.b); got != c.want {
			t.Errorf("severityGE(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}
