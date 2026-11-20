// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package flowlog

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

type diskLog struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

// Load reads a sidecar written by Save. A missing file is not an error.
// A corrupt file leaves the log empty and returns the decode error so the
// controller can start; the caller decides whether to ignore it.
// No-op when a non-JSON backend is attached.
func (l *Log) Load(path string) error {
	if l == nil || path == "" || l.backend != nil {
		return nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var disk diskLog
	if err := json.Unmarshal(b, &disk); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recs = disk.Records
	l.pruneLocked(time.Now().UTC())
	l.dirty = false
	return nil
}

// Save writes the current deltas atomically. The baseline map is not
// stored; the next report after a restart starts a new baseline.
// No-op when a non-JSON backend is attached.
func (l *Log) Save(path string) error {
	if l == nil || path == "" || l.backend != nil {
		return nil
	}
	return l.save(path, 0)
}

// SaveDebounced writes at most once per interval, and only after a new
// delta landed. Safe to call on every agent report.
// No-op when a non-JSON backend is attached.
func (l *Log) SaveDebounced(path string, every time.Duration) error {
	if l == nil || path == "" || l.backend != nil {
		return nil
	}
	if every <= 0 {
		every = 15 * time.Second
	}
	l.mu.Lock()
	due := l.dirty && (l.lastSave.IsZero() || time.Since(l.lastSave) >= every)
	l.mu.Unlock()
	if !due {
		return nil
	}
	return l.save(path, every)
}

func (l *Log) save(path string, every time.Duration) error {
	l.saveMu.Lock()
	defer l.saveMu.Unlock()
	l.mu.Lock()
	if every > 0 && (!l.dirty || (!l.lastSave.IsZero() && time.Since(l.lastSave) < every)) {
		l.mu.Unlock()
		return nil
	}
	recs := append([]Record(nil), l.recs...)
	gen := l.gen
	l.mu.Unlock()
	if err := writeFlowFile(path, recs); err != nil {
		return err
	}
	l.mu.Lock()
	if l.gen == gen {
		l.dirty = false
	}
	l.lastSave = time.Now()
	l.mu.Unlock()
	return nil
}

func writeFlowFile(path string, recs []Record) error {
	b, err := json.Marshal(diskLog{Version: 1, Records: recs})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
