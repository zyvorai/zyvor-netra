//go:build linux

package procmeta

import (
	"os"
	"sort"
	"sync"
	"time"
)

// Cache memoizes Meta values by Identity.
//
// The cache key is {PID, StartTime}, not PID alone, so a reused PID does
// not return a stale entry. On a hit the cache still reads /proc/PID/stat
// to confirm StartTime has not changed; that read is the smallest of the
// /proc files and is what makes the cache safe.
//
// The value stored in the cache is shared. Callers must treat the returned
// *Meta as read-only.
type Cache struct {
	mu      sync.Mutex
	entries map[Identity]cacheEntry
	ttl     time.Duration
	max     int
}

type cacheEntry struct {
	meta *Meta
	at   time.Time
}

// NewCache returns a cache. A non-positive ttl defaults to 30s; a
// non-positive max defaults to 8192 entries. Both bounds are enforced: an
// entry older than ttl is not served, and the map is trimmed when it
// exceeds max.
func NewCache(ttl time.Duration, max int) *Cache {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if max <= 0 {
		max = 8192
	}
	return &Cache{
		entries: make(map[Identity]cacheEntry),
		ttl:     ttl,
		max:     max,
	}
}

// Get returns metadata for pid, using the cache when possible. Returns
// ErrNoProcess if pid does not exist.
func (c *Cache) Get(pid int) (*Meta, error) {
	// Read stat to learn identity. This is cheap and necessary: it is the
	// only way to distinguish a cache hit from a PID that has been reused
	// since the entry was written.
	statB, err := os.ReadFile(statPath(pid))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoProcess
		}
		return nil, err
	}
	_, startJiffies, _, err := parseStat(pid, statB)
	if err != nil {
		return nil, err
	}
	id := Identity{PID: pid, StartTime: startJiffies}

	c.mu.Lock()
	if e, ok := c.entries[id]; ok && time.Since(e.at) < c.ttl {
		c.mu.Unlock()
		return e.meta, nil
	}
	c.mu.Unlock()

	// Miss. Reuse the stat bytes we already read.
	m, err := readFromStat(pid, statB)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	if len(c.entries) >= c.max {
		c.evictLocked()
	}
	c.entries[id] = cacheEntry{meta: m, at: time.Now()}
	c.mu.Unlock()

	return m, nil
}

// Sweep removes entries older than the TTL. Callers with a long-lived
// cache should call this periodically; Get only trims on overflow.
func (c *Cache) Sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-c.ttl)
	for k, e := range c.entries {
		if e.at.Before(cutoff) {
			delete(c.entries, k)
		}
	}
}

// Len returns the current number of cached entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// evictLocked removes expired entries, and if the map is still at or above
// max, drops the oldest quarter. Called with c.mu held.
func (c *Cache) evictLocked() {
	cutoff := time.Now().Add(-c.ttl)
	for k, e := range c.entries {
		if e.at.Before(cutoff) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < c.max {
		return
	}
	type ke struct {
		k  Identity
		at time.Time
	}
	all := make([]ke, 0, len(c.entries))
	for k, e := range c.entries {
		all = append(all, ke{k, e.at})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	drop := len(all) / 4
	if drop == 0 {
		drop = 1
	}
	for i := 0; i < drop; i++ {
		delete(c.entries, all[i].k)
	}
}
