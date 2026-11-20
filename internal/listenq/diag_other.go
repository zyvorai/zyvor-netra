// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package listenq

import "errors"

// ErrUnsupported is returned on platforms without inet_diag.
var ErrUnsupported = errors.New("listen queue sampling requires Linux")

// Dump always fails off Linux.
func Dump() ([]Listener, error) { return nil, ErrUnsupported }
