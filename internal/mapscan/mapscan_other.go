// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

// Package mapscan reads every entry of a BPF hash map cheaply (Linux only).
package mapscan

import (
	"errors"

	"github.com/cilium/ebpf"
)

// Stats describes one Scan.
type Stats struct {
	Entries  int
	Syscalls int
	Batched  bool
}

// Scan is unavailable off Linux.
func Scan(*ebpf.Map, func(key, val []byte) bool) (Stats, error) {
	return Stats{}, errors.New("mapscan requires Linux")
}
