// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package flowlog

import (
	"strings"
	"time"
)

// Backend is durable (or in-memory) storage for flow deltas after Ingest
// computes them. The default Log keeps records in memory and a JSON
// sidecar; the optional SQLite backend writes incrementally.
type Backend interface {
	Append(recs []Record) error
	Query(q Query) Result
	Limitations() []string
	Len() int
	Close() error
}

// BackendName selects the flow history persistence mode.
type BackendName string

const (
	BackendJSON   BackendName = "json"
	BackendSQLite BackendName = "sqlite"
)

// ParseBackend reads NETRA_FLOW_BACKEND. Empty means json.
func ParseBackend(s string) BackendName {
	switch BackendName(strings.ToLower(strings.TrimSpace(s))) {
	case BackendSQLite:
		return BackendSQLite
	default:
		return BackendJSON
	}
}

// Options configure retention for any backend.
type Options struct {
	Retain   time.Duration
	Max      int
	MaxBytes int64 // sqlite only; 0 = no byte budget
}

// Normalize fills defaults.
func (o Options) Normalize() Options {
	if o.Retain <= 0 {
		o.Retain = DefaultRetain
	}
	if o.Max <= 0 {
		o.Max = DefaultMax
	}
	return o
}
