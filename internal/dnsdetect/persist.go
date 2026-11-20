// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package dnsdetect

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

// PersistSnapshot is the HA warm-start payload: active findings only.
// Rolling domain state is not persisted (rebuilds from new observes).
type PersistSnapshot struct {
	Version  int       `json:"version"`
	SavedAt  time.Time `json:"savedAt"`
	Findings []Finding `json:"findings"`
}

const persistVersion = 1

// ExportPersist copies TTL-live findings for disk.
func (d *Detector) ExportPersist() PersistSnapshot {
	if d == nil {
		return PersistSnapshot{Version: persistVersion, Findings: []Finding{}}
	}
	return PersistSnapshot{
		Version:  persistVersion,
		SavedAt:  time.Now().UTC(),
		Findings: d.Findings(),
	}
}

// ImportPersist merges non-expired findings. Does not clear existing
// findings; newer LastSeen wins on the same key. Never triggers mitigate.
func (d *Detector) ImportPersist(snap PersistSnapshot) int {
	if d == nil || len(snap.Findings) == 0 {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := time.Now().Add(-d.cfg.FindingsTTL)
	imported := 0
	for _, f := range snap.Findings {
		if f.LastSeen.Before(cutoff) || f.ID == "" {
			continue
		}
		key := findingKey{ftype: f.Type, registered: f.Domain, namespace: f.Namespace, pod: f.Pod}
		if prev, ok := d.findings[key]; ok && !prev.LastSeen.Before(f.LastSeen) {
			continue
		}
		cp := f
		cp.Signals = append([]string(nil), f.Signals...)
		cp.ExampleNames = append([]string(nil), f.ExampleNames...)
		d.findings[key] = &cp
		imported++
	}
	return imported
}

// SavePersist writes findings atomically beside the controller state file.
func (d *Detector) SavePersist(path string) error {
	if d == nil || path == "" {
		return nil
	}
	b, err := json.Marshal(d.ExportPersist())
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadPersist reads a sidecar. Missing file is fine.
func (d *Detector) LoadPersist(path string) (int, error) {
	if d == nil || path == "" {
		return 0, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var snap PersistSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return 0, err
	}
	return d.ImportPersist(snap), nil
}
