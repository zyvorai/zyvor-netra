// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package sslprobe

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// ErrUnsupported is returned on platforms without eBPF.
var ErrUnsupported = errors.New("TLS plaintext sampling requires Linux")

// Options mirrors the Linux type so callers compile everywhere.
type Options struct {
	ObjectPath string
	ProcRoot   string
	MinGap     time.Duration
	Comms      []string
	Log        *slog.Logger
}

// KernelStats are the in-kernel counters.
type KernelStats struct{ Eligible, Emitted, RateLimited, RingbufFull, ReadFail, CommFiltered uint64 }

// Prober is never constructed off Linux.
type Prober struct{}

// Load always fails off Linux.
func Load(Options) (*Prober, error) { return nil, ErrUnsupported }

// Scan always fails off Linux.
func (*Prober) Scan() ([]string, error) { return nil, ErrUnsupported }

// Libraries is empty off Linux.
func (*Prober) Libraries() []string { return nil }

// Run is a no-op.
func (*Prober) Run(context.Context, func(Event)) {}

// KernelStats always fails off Linux.
func (*Prober) KernelStats() (KernelStats, error) { return KernelStats{}, ErrUnsupported }

// ProgramStats always fails off Linux.
func (*Prober) ProgramStats() (uint64, time.Duration, error) { return 0, 0, ErrUnsupported }

// Close is a no-op.
func (*Prober) Close() error { return nil }
