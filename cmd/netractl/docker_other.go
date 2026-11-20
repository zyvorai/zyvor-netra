//go:build !linux

// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "fmt"

func localDockerCgroup(dockerContainer) (uint64, error) {
	return 0, fmt.Errorf("Docker discovery requires Linux host PID and cgroup-v2 namespaces; Docker Desktop host discovery is not supported")
}
