// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package tlsfp

import (
	"sync"
	"time"
)

// Observation is one fingerprint attributed to a capture node (and
// optional workload fields when known).
type Observation struct {
	Fingerprint
	Node      string    `json:"node,omitempty"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	Count     uint64    `json:"count"`
}

// Detector holds a bounded set of observed fingerprints. Observe-only.
type Detector struct {
	mu      sync.Mutex
	byJA3   map[string]*Observation
	order   []string
	maxSize int
}

// NewDetector caps distinct JA3 hashes (default 2048).
func NewDetector(maxSize int) *Detector {
	if maxSize <= 0 {
		maxSize = 2048
	}
	return &Detector{byJA3: map[string]*Observation{}, maxSize: maxSize}
}

// ObserveFrame tries to parse a ClientHello from one capture frame.
func (d *Detector) ObserveFrame(node string, frame []byte) {
	if d == nil {
		return
	}
	hello := ExtractClientHello(frame)
	if hello == nil {
		return
	}
	fp, err := ParseClientHello(hello)
	if err != nil || fp == nil || fp.JA3 == "" {
		return
	}
	d.Observe(node, *fp)
}

// Observe records a parsed fingerprint.
func (d *Detector) Observe(node string, fp Fingerprint) {
	if d == nil || fp.JA3 == "" {
		return
	}
	now := time.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()
	if o, ok := d.byJA3[fp.JA3]; ok {
		o.LastSeen = now
		o.Count++
		if node != "" {
			o.Node = node
		}
		if fp.SNI != "" {
			o.SNI = fp.SNI
		}
		if fp.JA4 != "" {
			o.JA4 = fp.JA4
		}
		if fp.ECH {
			o.ECH = true
		}
		return
	}
	for len(d.order) >= d.maxSize {
		old := d.order[0]
		d.order = d.order[1:]
		delete(d.byJA3, old)
	}
	d.order = append(d.order, fp.JA3)
	d.byJA3[fp.JA3] = &Observation{
		Fingerprint: fp, Node: node, FirstSeen: now, LastSeen: now, Count: 1,
	}
}

// Snapshot returns observations newest-last-seen first.
func (d *Detector) Snapshot(limit int) []Observation {
	if d == nil {
		return nil
	}
	if limit <= 0 {
		limit = 200
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Observation, 0, len(d.byJA3))
	for _, o := range d.byJA3 {
		out = append(out, *o)
	}
	// simple insertion by LastSeen desc
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].LastSeen.After(out[i].LastSeen) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Stats is a compact summary.
func (d *Detector) Stats() map[string]any {
	if d == nil {
		return map[string]any{"enabled": false, "uniqueJa3": 0}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return map[string]any{"enabled": true, "uniqueJa3": len(d.byJA3), "cap": d.maxSize}
}
