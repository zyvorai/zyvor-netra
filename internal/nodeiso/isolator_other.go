// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package nodeiso

import (
	"errors"
	"log/slog"

	"github.com/zyvorai/netra/internal/models"
)

// Options mirrors the Linux type so callers compile everywhere.
type Options struct {
	ObjectPath string
	Interfaces []string
	LoadOnly   bool
	Log        *slog.Logger
}

// Isolator is unavailable off Linux.
type Isolator struct{}

// ErrUnsupported reports that node isolation needs Linux.
var ErrUnsupported = errors.New("node isolation requires Linux")

func Load(Options) (*Isolator, error)  { return nil, ErrUnsupported }
func (i *Isolator) Attached() []string { return nil }
func (i *Isolator) Apply(*models.NodeIsolationSpec, []models.NodeIsolationRule, string) error {
	return ErrUnsupported
}
func (i *Isolator) Snapshot(int) (*models.NodeIsolationStatus, error) { return nil, ErrUnsupported }
func (i *Isolator) Close() error                                      { return nil }
