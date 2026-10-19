// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"net/http"
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

// enforceScope rejects scoped callers that cannot access ns/cluster/tenant.
// Unrestricted principals always pass. Returns false when a response was written.
func (s *Server) enforceScope(w http.ResponseWriter, r *http.Request, ns, cluster, tenant string) bool {
	p, ok := principalFrom(r.Context())
	if !ok || p.Unrestricted() {
		return true
	}
	if cluster == "" {
		cluster = localCluster()
	}
	if tenant == "" {
		tenant = localTenant()
	}
	if p.Allows(ns, cluster, tenant) {
		return true
	}
	s.metricsData.rbacDenied.Add(1)
	errorJSON(w, http.StatusForbidden, "scope does not allow this resource")
	return false
}

// requireUnrestricted blocks scoped service/OIDC credentials from admin-only
// fleet-wide surfaces (exec, mode changes, etc.).
func (s *Server) requireUnrestricted(w http.ResponseWriter, r *http.Request) bool {
	p, ok := principalFrom(r.Context())
	if !ok || p.Unrestricted() {
		return true
	}
	s.metricsData.rbacDenied.Add(1)
	errorJSON(w, http.StatusForbidden, "scoped credentials cannot use this endpoint")
	return false
}

func filterStrings(allowed, values []string) []string {
	if len(allowed) == 0 {
		return values
	}
	var out []string
	for _, v := range values {
		for _, a := range allowed {
			if strings.EqualFold(a, v) {
				out = append(out, v)
				break
			}
		}
	}
	return out
}
