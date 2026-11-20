// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package netlinkwatch

import (
	"context"
	"errors"
)

// Start reports that RTNL is a Linux facility.
func Start(context.Context, int) (*Watcher, error) {
	return nil, errors.New("netlink watcher requires Linux")
}
