// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package intel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const HistoryLimit = 16

var ErrConflict = errors.New("intel feed revision changed")

type Revision struct {
	Revision  uint64     `json:"revision"`
	UpdatedAt time.Time  `json:"updatedAt"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Source    string     `json:"source"`
	Note      string     `json:"note,omitempty"`
	Entries   []Entry    `json:"entries"`
}
type Status struct {
	Count              int        `json:"count"`
	UpdatedAt          time.Time  `json:"updatedAt,omitempty"`
	Source             string     `json:"source,omitempty"`
	Note               string     `json:"note,omitempty"`
	Empty              bool       `json:"empty"`
	Revision           uint64     `json:"revision"`
	ExpiresAt          *time.Time `json:"expiresAt,omitempty"`
	Expired            bool       `json:"expired"`
	Persistent         bool       `json:"persistent"`
	JournalUnavailable bool       `json:"journalUnavailable"`
	LastRefresh        *time.Time `json:"lastRefresh,omitempty"`
	RefreshError       string     `json:"refreshError,omitempty"`
}

// Feed serializes operator and scheduler updates. Disk publication happens
// before memory publication, so failed writes preserve the last good revision.
type Feed struct {
	mu           sync.RWMutex
	history      []Revision
	path         string
	unavailable  bool
	lastRefresh  time.Time
	refreshError string
}

func Open(path string) (*Feed, error) {
	f := &Feed{path: path}
	if path == "" {
		return f, nil
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		f.unavailable = true
		return f, err
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, 8<<20+1))
	if err == nil && len(b) > 8<<20 {
		err = errors.New("intel journal too large")
	}
	var h []Revision
	if err == nil {
		err = json.Unmarshal(b, &h)
	}
	if err == nil {
		if len(h) == 0 || len(h) > HistoryLimit {
			err = errors.New("invalid intel history size")
		}
		for i, r := range h {
			p := normalize(r.Entries)
			if r.Revision == 0 || r.UpdatedAt.IsZero() || (i > 0 && r.Revision != h[i-1].Revision+1) || p.Dropped != 0 || p.Count != len(r.Entries) || len(r.Source) > 512 || len(r.Note) > 1024 {
				err = errors.New("invalid intel journal revision")
				break
			}
			if r.ExpiresAt != nil && !r.ExpiresAt.After(r.UpdatedAt) {
				err = errors.New("invalid intel journal expiry")
				break
			}
			h[i].Entries = p.Entries
		}
	}
	if err != nil {
		f.unavailable = true
		return f, fmt.Errorf("intel journal: %w", err)
	}
	f.history = h
	return f, nil
}

func (f *Feed) currentLocked() Revision {
	if len(f.history) == 0 {
		return Revision{}
	}
	return f.history[len(f.history)-1]
}
func expired(r Revision, now time.Time) bool { return r.ExpiresAt != nil && !now.Before(*r.ExpiresAt) }
func cloneRevision(r Revision) Revision {
	r.Entries = append([]Entry(nil), r.Entries...)
	if r.ExpiresAt != nil {
		t := *r.ExpiresAt
		r.ExpiresAt = &t
	}
	return r
}
func (f *Feed) statusLocked() Status {
	r := f.currentLocked()
	exp := expired(r, time.Now())
	count := len(r.Entries)
	if exp {
		count = 0
	}
	r = cloneRevision(r)
	var last *time.Time
	if !f.lastRefresh.IsZero() {
		t := f.lastRefresh
		last = &t
	}
	return Status{Count: count, Empty: count == 0, Revision: r.Revision, UpdatedAt: r.UpdatedAt, Source: r.Source, Note: r.Note, ExpiresAt: r.ExpiresAt, Expired: exp, Persistent: f.path != "", JournalUnavailable: f.unavailable, LastRefresh: last, RefreshError: f.refreshError}
}
func (f *Feed) Status() Status {
	if f == nil {
		return Status{Empty: true}
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.statusLocked()
}
func (f *Feed) Entries() []Entry {
	if f == nil {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	r := f.currentLocked()
	if expired(r, time.Now()) {
		return nil
	}
	return append([]Entry(nil), r.Entries...)
}
func (f *Feed) History() []Revision {
	if f == nil {
		return []Revision{}
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]Revision, len(f.history))
	for i, r := range f.history {
		out[i] = cloneRevision(r)
	}
	return out
}
func (f *Feed) publishLocked(r Revision, expected *uint64, ttl time.Duration) (Status, error) {
	if f.unavailable {
		return f.statusLocked(), errors.New("intel journal unavailable; repair it before updating")
	}
	cur := f.currentLocked()
	if expected != nil && *expected != cur.Revision {
		return f.statusLocked(), ErrConflict
	}
	r.Revision = cur.Revision + 1
	r.UpdatedAt = time.Now().UTC()
	if ttl > 0 {
		t := r.UpdatedAt.Add(ttl)
		r.ExpiresAt = &t
	}
	if len(r.Source) > 512 || len(r.Note) > 1024 {
		return f.statusLocked(), errors.New("intel source/note too long")
	}
	h := append(append([]Revision(nil), f.history...), cloneRevision(r))
	if len(h) > HistoryLimit {
		h = h[len(h)-HistoryLimit:]
	}
	if f.path != "" {
		b, err := json.Marshal(h)
		if err != nil {
			return f.statusLocked(), err
		}
		if err = writeJournal(f.path, b); err != nil {
			return f.statusLocked(), err
		}
	}
	f.history = h
	return f.statusLocked(), nil
}
func writeJournal(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".netra-intel-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(b); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Put replaces the feed. TTL zero preserves the operator's non-expiring mode.
func (f *Feed) Put(p Preview, source, note string, ttl time.Duration, expected *uint64) (Status, error) {
	if f == nil {
		return Status{Empty: true}, errors.New("intel unavailable")
	}
	if ttl < 0 || ttl > 30*24*time.Hour {
		return f.Status(), errors.New("ttl must be between zero and 720h")
	}
	normalized := normalize(p.Entries)
	if normalized.Dropped != 0 {
		return f.Status(), errors.New("invalid or duplicate intel entries")
	}
	r := Revision{Source: source, Note: note, Entries: normalized.Entries}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.publishLocked(r, expected, ttl)
}
func (f *Feed) Rollback(revision uint64, expected *uint64) (Status, error) {
	if f == nil {
		return Status{Empty: true}, errors.New("intel unavailable")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.history {
		if r.Revision != revision {
			continue
		}
		if expired(r, time.Now()) {
			return f.statusLocked(), errors.New("cannot restore expired intel")
		}
		r.Note = fmt.Sprintf("rollback to revision %d", revision)
		return f.publishLocked(r, expected, 0)
	}
	return f.statusLocked(), errors.New("revision not retained")
}

// Compatibility for in-process callers; HTTP writes use Put and surface errors.
func (f *Feed) Set(p Preview, source, note string) Status {
	s, _ := f.Put(p, source, note, 0, nil)
	return s
}
func (f *Feed) Clear() Status { s, _ := f.Put(Preview{}, "operator", "cleared", 0, nil); return s }
