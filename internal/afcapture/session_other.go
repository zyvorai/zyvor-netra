// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package afcapture

import (
	"context"
	"errors"

	"github.com/zyvorai/netra/internal/capture"
)

var errUnimplemented = errors.New("afcapture: AF_PACKET capture is Linux-only")

// Open always fails off Linux — see probe_other.go's Available(), which a
// caller should check first; this stub exists purely so go build ./...
// stays clean on non-Linux dev machines.
func Open(_ context.Context, _ []string, _ capture.SpecValue) (*Session, error) {
	return nil, errUnimplemented
}
