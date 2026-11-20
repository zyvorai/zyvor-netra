// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package afcapture

// Available always reports false off Linux — AF_PACKET is Linux-only, and
// the agent only ever ships a Linux build; this stub exists purely so
// go build ./... stays clean on non-Linux dev machines.
func Available() bool { return false }
