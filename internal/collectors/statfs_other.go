// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package collectors

import "errors"

func platformStatfs(string) (fsUsage, error) {
	return fsUsage{}, errors.New("statfs is only collected on linux")
}
