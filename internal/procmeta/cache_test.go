//go:build linux

package procmeta

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestCacheHitReturnsSameValue(t *testing.T) {
	c := NewCache(time.Minute, 16)
	pid := os.Getpid()

	a, err := c.Get(pid)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Get(pid)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("second Get should return the cached pointer")
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}
}

func TestCacheNoProcess(t *testing.T) {
	c := NewCache(time.Minute, 16)
	_, err := c.Get(1<<31 - 1)
	if !errors.Is(err, ErrNoProcess) {
		t.Fatalf("want ErrNoProcess, got %v", err)
	}
}

func TestCacheSweep(t *testing.T) {
	c := NewCache(time.Nanosecond, 16)
	if _, err := c.Get(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 1 {
		t.Fatalf("Len = %d, want 1", c.Len())
	}
	time.Sleep(2 * time.Millisecond)
	c.Sweep()
	if c.Len() != 0 {
		t.Errorf("Sweep did not remove expired entry; Len = %d", c.Len())
	}
}

func TestCacheEvictsOldest(t *testing.T) {
	// Force eviction by filling past max with synthetic entries.
	c := NewCache(time.Hour, 4)
	now := time.Now()
	for i := 0; i < 4; i++ {
		c.entries[Identity{PID: i, StartTime: uint64(i)}] = cacheEntry{
			meta: &Meta{},
			at:   now.Add(time.Duration(i) * time.Second),
		}
	}
	c.mu.Lock()
	c.evictLocked()
	c.mu.Unlock()
	// Oldest quarter (1 entry) should be gone.
	if c.Len() != 3 {
		t.Errorf("after evict, Len = %d, want 3", c.Len())
	}
	if _, ok := c.entries[Identity{PID: 0, StartTime: 0}]; ok {
		t.Error("oldest entry should have been evicted")
	}
}

func TestCacheDefaults(t *testing.T) {
	c := NewCache(0, 0)
	if c.ttl != 30*time.Second {
		t.Errorf("default ttl = %v", c.ttl)
	}
	if c.max != 8192 {
		t.Errorf("default max = %d", c.max)
	}
}

func TestCacheExpiredEntryIsRefreshed(t *testing.T) {
	c := NewCache(time.Nanosecond, 16)
	pid := os.Getpid()

	a, err := c.Get(pid)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	b, err := c.Get(pid)
	if err != nil {
		t.Fatal(err)
	}
	// After TTL expiry, a fresh read should produce a distinct pointer.
	if a == b {
		t.Error("expired entry should have been refreshed, not served")
	}
	if !a.Identity.Same(b.Identity) {
		t.Error("same process must produce the same identity across reads")
	}
}
