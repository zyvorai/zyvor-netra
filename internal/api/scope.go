// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"os"
	"strings"
)

// Allows reports whether p may see/act on the given namespace, cluster and
// tenant. Empty dimensions on the principal mean unrestricted. Empty
// resource fields are allowed only when that dimension is unrestricted
// (list endpoints filter; mutates that omit a namespace are denied when
// namespace-scoped).
func (p principal) Allows(ns, cluster, tenant string) bool {
	if !p.allowsDim(p.Namespaces, ns) {
		return false
	}
	if !p.allowsDim(p.Clusters, cluster) {
		return false
	}
	if !p.allowsDim(p.Tenants, tenant) {
		return false
	}
	return true
}

func (p principal) allowsDim(allowed []string, value string) bool {
	if len(allowed) == 0 {
		return true
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, a := range allowed {
		if strings.EqualFold(a, value) {
			return true
		}
	}
	return false
}

// Unrestricted is true when the principal has no scope limits.
func (p principal) Unrestricted() bool {
	return len(p.Namespaces) == 0 && len(p.Clusters) == 0 && len(p.Tenants) == 0
}

func (p principal) AllowsNamespace(ns string) bool {
	return p.allowsDim(p.Namespaces, ns)
}

func localCluster() string {
	return strings.TrimSpace(os.Getenv("NETRA_CLUSTER_NAME"))
}

func localTenant() string {
	return strings.TrimSpace(os.Getenv("NETRA_CLUSTER_TENANT"))
}
