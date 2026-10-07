// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package intel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func preview(t *testing.T, raw string) Preview {
	t.Helper()
	p, e := Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestCanonicalNormalizationAndTruncation(t *testing.T) {
	p := preview(t, "cidr,192.0.2.19/24\ncidr,192.0.2.0/24\ndns,EXAMPLE.COM.\ndns,example.com\nip,2001:0db8::1\nip,2001:db8::1\ndns,bad..name\n")
	if p.Count != 3 || p.Dropped != 4 {
		t.Fatalf("%+v", p)
	}
	p = preview(t, "192.0.2.1\n"+strings.Repeat("x", 70000))
	if p.Dropped != 1 {
		t.Fatalf("scanner error lost: %+v", p)
	}
}
func TestJournalRevisionRollbackAndCopies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intel.json")
	f, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Put(preview(t, "192.0.2.1"), "unit", "", time.Hour, nil); e != nil {
		t.Fatal(e)
	}
	h := f.History()
	h[0].Entries[0].Value = "mutated"
	*h[0].ExpiresAt = time.Time{}
	if f.Entries()[0].Value != "192.0.2.1" || f.Status().Expired {
		t.Fatal("snapshot aliases feed")
	}
	if _, e = f.Put(preview(t, "192.0.2.2"), "unit", "", 0, nil); e != nil {
		t.Fatal(e)
	}
	expected := uint64(1)
	if _, e = f.Rollback(1, &expected); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	expected = 2
	s, e := f.Rollback(1, &expected)
	if e != nil || s.Revision != 3 || f.Entries()[0].Value != "192.0.2.1" {
		t.Fatalf("%+v %v", s, e)
	}
	recovered, e := Open(path)
	if e != nil || recovered.Status().Revision != 3 || recovered.Status().ExpiresAt == nil {
		t.Fatalf("%+v %v", recovered, e)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions %v", info.Mode())
	}
	for i := 0; i < HistoryLimit+2; i++ {
		if _, e = f.Put(preview(t, "192.0.2.3"), "unit", "", 0, nil); e != nil {
			t.Fatal(e)
		}
	}
	if len(f.History()) != HistoryLimit {
		t.Fatal("history unbounded")
	}
	if _, e = f.Rollback(1, nil); e == nil {
		t.Fatal("restored evicted revision")
	}
}
func TestExpiredFeedAndCorruptJournal(t *testing.T) {
	f := &Feed{}
	f.Set(preview(t, "192.0.2.1"), "unit", "")
	past := time.Now().Add(-time.Second)
	f.mu.Lock()
	f.history[0].ExpiresAt = &past
	f.mu.Unlock()
	if len(f.Entries()) != 0 || !f.Status().Expired || f.Status().Count != 0 {
		t.Fatal("expired entries active")
	}
	if _, e := f.Rollback(1, nil); e == nil {
		t.Fatal("revived expired feed")
	}
	path := filepath.Join(t.TempDir(), "broken")
	os.WriteFile(path, []byte("broken"), 0600)
	bad, e := Open(path)
	if e == nil || !bad.Status().JournalUnavailable {
		t.Fatal("corrupt journal accepted")
	}
	if _, e = bad.Put(preview(t, "192.0.2.2"), "unit", "", 0, nil); e == nil {
		t.Fatal("overwrote broken journal")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "broken" {
		t.Fatal("corrupt state overwritten")
	}
}
func TestPersistenceFailurePreservesMemory(t *testing.T) {
	f := &Feed{}
	f.Set(preview(t, "192.0.2.1"), "unit", "")
	f.path = filepath.Join(t.TempDir(), "missing", "feed")
	if _, e := f.Put(preview(t, "192.0.2.2"), "unit", "", 0, nil); e == nil {
		t.Fatal("write unexpectedly succeeded")
	}
	if f.Status().Revision != 1 || f.Entries()[0].Value != "192.0.2.1" {
		t.Fatal("failed write published")
	}
}
func TestConcurrentCASPublishesOnce(t *testing.T) {
	f := &Feed{}
	p := preview(t, "192.0.2.1")
	expected := uint64(0)
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := f.Put(p, "unit", "", 0, &expected); results <- e }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		} else if !errors.Is(e, ErrConflict) {
			t.Fatal(e)
		}
	}
	if successes != 1 || f.Status().Revision != 1 {
		t.Fatalf("successes=%d", successes)
	}
}
func TestRefreshStrictValidationNoRedirectAndRetainsLastGood(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		good       bool
	}{
		{"valid", "192.0.2.2", 200, true}, {"empty", "", 200, false}, {"partial", "192.0.2.2\nnot valid", 200, false}, {"duplicate", "192.0.2.2\n192.0.2.2", 200, false}, {"oversize", strings.Repeat("#", (1<<20)+1), 200, false}, {"status", "192.0.2.2", 503, false}, {"scanner", "192.0.2.2\n" + strings.Repeat("x", 70000), 200, false}, {"redirect", "192.0.2.2", 302, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			f := &Feed{}
			f.Set(preview(t, "192.0.2.1"), "unit", "")
			c := RefreshConfig{URL: srv.URL + "?secret=token", Interval: time.Minute, TTL: time.Hour}
			e := f.Refresh(context.Background(), c, srv.Client().Transport)
			if (e == nil) != tc.good || calls != 1 {
				t.Fatalf("error=%v calls=%d", e, calls)
			}
			if tc.good {
				if f.Status().Revision != 2 || strings.Contains(f.Status().Source, "token") || f.Status().ExpiresAt == nil {
					t.Fatalf("%+v", f.Status())
				}
			} else if f.Status().Revision != 1 || f.Entries()[0].Value != "192.0.2.1" || f.Status().RefreshError == "" {
				t.Fatalf("%+v", f.Status())
			}
		})
	}
}
func TestRefreshCASAndCancellation(t *testing.T) {
	f := &Feed{}
	p := preview(t, "192.0.2.1")
	f.Set(p, "unit", "")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.Set(p, "operator", ""); fmt.Fprint(w, "192.0.2.2") }))
	defer srv.Close()
	c := RefreshConfig{URL: srv.URL, Interval: time.Minute, TTL: time.Hour}
	if e := f.Refresh(context.Background(), c, srv.Client().Transport); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if f.Status().Source != "operator" {
		t.Fatal("refresh overwrote operator")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.RunRefresh(ctx, c)
	if f.Status().Revision != 2 {
		t.Fatal("cancelled loop ran")
	}
	c.URL = "http://example.com"
	if c.Validate() == nil {
		t.Fatal("http accepted")
	}
	c.URL = "https://user:pass@example.com"
	if c.Validate() == nil {
		t.Fatal("userinfo accepted")
	}
}
