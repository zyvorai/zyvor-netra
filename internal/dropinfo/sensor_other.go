// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package dropinfo

import (
	"errors"
	"log/slog"
	"time"

	"github.com/zyvorai/netra/internal/ksym"
	"github.com/zyvorai/netra/internal/tpformat"
)

// ErrUnsupported is returned on platforms without eBPF.
var ErrUnsupported = errors.New("drop info sensor requires Linux")

// Options mirrors the Linux type so callers compile everywhere.
type Options struct {
	ObjectPath string
	ReadFormat func(group, event string) (*tpformat.Format, error)
	BTFPath    string
	Symbols    *ksym.Resolver
	Log        *slog.Logger
}

// Sensor is never constructed off Linux.
type Sensor struct{}

// Load always fails off Linux.
func Load(Options) (*Sensor, error) { return nil, ErrUnsupported }

// Snapshot always fails off Linux.
func (*Sensor) Snapshot(int, int) (*Snapshot, error) { return nil, ErrUnsupported }

// Stats always fails off Linux.
func (*Sensor) Stats() (uint64, time.Duration, error) { return 0, 0, ErrUnsupported }

// Close is a no-op.
func (*Sensor) Close() error { return nil }
