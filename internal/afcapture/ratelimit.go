// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package afcapture

import (
	"sync"
	"time"
)

// rateLimiter is a simple 1-second sliding-window packet cap, the
// userspace equivalent of bpf/netra_capture.c's rate_allow() — necessary
// because there is no in-kernel capture_rate map for this backend; every
// filter-matching packet has already cost one syscall round-trip and copy
// by the time this runs (see docs/capture.md's tradeoff note). Portable
// (no Linux-specific code) so it's unit-testable without a real socket.
type rateLimiter struct {
	maxPPS      uint32
	mu          sync.Mutex
	windowStart int64
	count       uint32
}

func newRateLimiter(maxPPS uint32) *rateLimiter { return &rateLimiter{maxPPS: maxPPS} }

func (r *rateLimiter) allow() bool {
	if r.maxPPS == 0 {
		return true
	}
	now := time.Now().Unix()
	r.mu.Lock()
	defer r.mu.Unlock()
	if now != r.windowStart {
		r.windowStart = now
		r.count = 0
	}
	if r.count >= r.maxPPS {
		return false
	}
	r.count++
	return true
}
