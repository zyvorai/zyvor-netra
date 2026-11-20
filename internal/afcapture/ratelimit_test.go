// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package afcapture

import "testing"

func TestRateLimiter_ZeroMeansUnlimited(t *testing.T) {
	r := newRateLimiter(0)
	for i := range 10000 {
		if !r.allow() {
			t.Fatalf("maxPPS=0 should never deny, denied at i=%d", i)
		}
	}
}

func TestRateLimiter_CapsWithinWindow(t *testing.T) {
	r := newRateLimiter(3)
	for i := range 3 {
		if !r.allow() {
			t.Fatalf("expected allow #%d within cap", i)
		}
	}
	if r.allow() {
		t.Fatal("expected the 4th call within the same window to be denied")
	}
}

func TestRateLimiter_ResetsOnNewWindow(t *testing.T) {
	r := newRateLimiter(1)
	if !r.allow() {
		t.Fatal("expected first call to be allowed")
	}
	if r.allow() {
		t.Fatal("expected second call in the same window to be denied")
	}
	// Simulate the window rolling over without a real sleep.
	r.mu.Lock()
	r.windowStart -= 2
	r.mu.Unlock()
	if !r.allow() {
		t.Fatal("expected a new window to reset the counter")
	}
}
