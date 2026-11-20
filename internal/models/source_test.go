// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package models

import "testing"

func TestCanonicalSourceWorkloadWinsOverPod(t *testing.T) {
	got := CanonicalSource("prod", "api-1", "Deployment", "api", 42)
	if got != "workload:prod:deployment:api" {
		t.Fatalf("got %q", got)
	}
}

func TestCanonicalSourceDefaultsWorkloadKind(t *testing.T) {
	got := CanonicalSource("prod", "", "", "api", 0)
	if got != "workload:prod:workload:api" {
		t.Fatalf("got %q", got)
	}
}

func TestCanonicalSourcePodFallback(t *testing.T) {
	got := CanonicalSource("prod", "api-1", "", "", 0)
	if got != "pod:prod:api-1" {
		t.Fatalf("got %q", got)
	}
}

func TestCanonicalSourceCgroupFallback(t *testing.T) {
	got := CanonicalSource("", "", "", "", 7)
	if got != "cgroup:7" {
		t.Fatalf("got %q", got)
	}
}

func TestCanonicalSourceNodeFallback(t *testing.T) {
	got := CanonicalSource("", "", "", "", 0)
	if got != "node" {
		t.Fatalf("got %q", got)
	}
}

// Namespace set with neither pod nor workload identifies nothing more
// specific than the cgroup/node fallback — this must not silently produce
// a malformed "pod:ns:" ID with an empty pod segment.
func TestCanonicalSourceNamespaceAloneFallsThrough(t *testing.T) {
	got := CanonicalSource("prod", "", "", "", 9)
	if got != "cgroup:9" {
		t.Fatalf("got %q, want cgroup fallback rather than a malformed pod ID", got)
	}
}
