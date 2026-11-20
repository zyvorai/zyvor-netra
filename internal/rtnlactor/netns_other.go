// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package rtnlactor

// SelfNetNS is 0 off Linux: there are no network namespaces to tell apart.
func SelfNetNS() uint32 { return 0 }
