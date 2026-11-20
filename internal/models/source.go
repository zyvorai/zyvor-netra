// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package models

import (
	"strconv"
	"strings"
)

// CanonicalSource is the one canonical source-ID scheme shared by
// internal/insights (baseline/recommend source keys, dependency-graph node
// IDs) and internal/store (rate-sample sources) — previously three
// independently-implemented copies of the same "workload:ns:kind:name" /
// "pod:ns:pod" / "cgroup:N" / "node" precedence, consolidated here so a
// future caller (e.g. internal/incident's cross-signal correlator) has one
// place to call instead of a fourth copy.
//
// Precedence: a namespace+workload pair wins over namespace+pod, which
// wins over a bare cgroup ID, which falls back to the literal "node" when
// none of the above identify anything more specific.
func CanonicalSource(ns, pod, kind, workload string, cgroup uint64) string {
	if ns != "" && workload != "" {
		if kind == "" {
			kind = "workload"
		}
		return "workload:" + ns + ":" + strings.ToLower(kind) + ":" + workload
	}
	if ns != "" && pod != "" {
		return "pod:" + ns + ":" + pod
	}
	if cgroup != 0 {
		return "cgroup:" + strconv.FormatUint(cgroup, 10)
	}
	return "node"
}
