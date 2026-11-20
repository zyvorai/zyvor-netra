// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package tcpevents

import (
	"errors"
	"log/slog"

	"github.com/zyvorai/netra/internal/tpformat"
)

// Options mirrors the Linux type so callers compile everywhere.
type Options struct {
	ObjectPath string
	ReadFormat func(group, event string) (*tpformat.Format, error)
	Log        *slog.Logger
}

// Sensor is unavailable off Linux.
type Sensor struct{}

// ErrUnsupported reports that TCP event tracepoints need Linux.
var ErrUnsupported = errors.New("TCP event tracepoints require Linux")

func Load(Options) (*Sensor, error)               { return nil, ErrUnsupported }
func (s *Sensor) Attached() []string              { return nil }
func (s *Sensor) Skipped() map[string]string      { return nil }
func (s *Sensor) Close() error                    { return nil }
func (s *Sensor) Snapshot(int) (*Snapshot, error) { return nil, ErrUnsupported }
