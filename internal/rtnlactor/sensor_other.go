// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package rtnlactor

import (
	"context"
	"errors"
	"log/slog"
)

// Options configures Load.
type Options struct {
	ObjectPath string
	BTFPath    string
	NetNS      uint32
	Log        *slog.Logger
}

// Sensor does not exist off Linux.
type Sensor struct{}

// Load reports that this needs the Linux kernel.
func Load(Options) (*Sensor, error) {
	return nil, errors.New("the rtnl actor sensor requires Linux")
}

func (*Sensor) Run(context.Context, func(Record)) {}
func (*Sensor) Dropped() (uint64, error)          { return 0, nil }
func (*Sensor) Close() error                      { return nil }
