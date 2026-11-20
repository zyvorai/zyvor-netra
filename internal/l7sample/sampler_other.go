// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package l7sample

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// ErrUnsupported is returned on platforms without eBPF.
var ErrUnsupported = errors.New("l7 sampling requires Linux")

// Options mirrors the Linux type so callers compile everywhere.
type Options struct {
	ObjectPath string
	CgroupPath string
	Ports      map[uint16]Protocol
	MinGap     time.Duration
	Log        *slog.Logger
}

// KernelStats are the in-kernel counters.
type KernelStats struct{ Eligible, Emitted, RateLimited, RingbufFull, LoadFail uint64 }

// Sampler is never constructed off Linux.
type Sampler struct{}

// Load always fails off Linux.
func Load(Options) (*Sampler, error) { return nil, ErrUnsupported }

// Run is a no-op.
func (*Sampler) Run(context.Context, func(Sample)) {}

// KernelStats always fails off Linux.
func (*Sampler) KernelStats() (KernelStats, error) { return KernelStats{}, ErrUnsupported }

// ProgramStats always fails off Linux.
func (*Sampler) ProgramStats() (uint64, time.Duration, error) { return 0, 0, ErrUnsupported }

// Close is a no-op.
func (*Sampler) Close() error { return nil }
