//go:build linux

// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"strings"
	"testing"
)

func TestDockerCgroupPath(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, path := range []string{"/docker/" + id, "/system.slice/docker-" + id + ".scope", "/user.slice/user-1000.slice/docker-" + id + ".scope"} {
		got, err := dockerCgroupPath("0::"+path+"\n", id)
		if err != nil || got != path {
			t.Fatal(got, err)
		}
	}
	for _, input := range []string{"0::/", "1:memory:/docker/" + id, "0::/docker/" + id[:12], "0::/docker/" + id + "-suffix", "0::/docker/../" + id, "0::docker/" + id, "0::/docker/" + id + "\n0::/docker/" + id} {
		if _, err := dockerCgroupPath(input, id); err == nil {
			t.Fatal("accepted", input)
		}
	}
}
