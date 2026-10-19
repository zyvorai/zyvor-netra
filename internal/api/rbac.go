// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/zyvorai/netra/internal/oidcauth"
)

// Role model. Callers authenticate either with one of the static keys
// (NETRA_API_KEY, NETRA_CHATOPS_API_KEY) — always admin, exactly as before —
// or, when OIDC is configured, with an IdP-issued JWT whose claims map to
// viewer < operator < admin.
//
// The required role is decided from the matched route pattern (r.Pattern), so
// it is one central table rather than a check scattered over ~200 handlers,
// and a request cannot dodge it by path tricks the mux would normalise away.
//
//   - Reads (GET/HEAD/OPTIONS) need viewer …
//   - … except packet-bearing reads, which need operator (operatorGET).
//   - Computations that only look, though they POST, need viewer (viewerPOST).
//   - Everything else that changes state needs operator …
//   - … except the admin-only set: consoles, enforcement posture, policy
//     apply, feature toggles and other fleet-wide changes (adminOnly).
//
// Anything not listed falls to the safe default for its method, so a newly
// added mutating route is operator-gated without anyone remembering to.

// adminOnly lists route patterns that need the admin role.
var adminOnly = map[string]bool{
	// Shells, log streams and consoles into workloads.
	"GET /api/v1/pods/{namespace}/{name}/exec": true,
	"GET /api/v1/pods/{namespace}/{name}/logs": true,
	"GET /api/v1/vms/{namespace}/{name}/vnc":   true,
	// Fleet-wide enforcement posture.
	"PUT /api/v1/ebpf/mode":                true,
	"PUT /api/v1/ebpf/scope":               true,
	"PUT /api/v1/ebpf/shield":              true,
	"PUT /api/v1/ebpf/netpol/config":       true,
	"PUT /api/v1/ebpf/netpol/default-deny": true,
	"PUT /api/v1/ebpf/netpol/v2/config":    true,
	// Node-scoped allow-only isolation; can drop all of a node's egress.
	"PUT /api/v1/ebpf/node-isolation/{node}": true,
	// Cluster policy and lockdown.
	"POST /api/v1/policies/apply":                                  true,
	"POST /api/v1/policies/lockdown":                               true,
	"POST /api/v1/policies/gitops/resync":                          true,
	"POST /api/v1/policies/history/import":                         true,
	"POST /api/v1/policies/{namespace}/{name}/rollback/{revision}": true,
	"DELETE /api/v1/policies/{namespace}/{name}":                   true,
	"DELETE /api/v1/policies/lockdown/{namespace}/{name}":          true,
	// Rewrites deployment env on the cluster.
	"POST /api/v1/features/{id}": true,
	// Threat-intel feed replaces block lists.
	"PUT /api/v1/intel/feed":    true,
	"DELETE /api/v1/intel/feed": true,
	"POST /api/v1/intel/apply":  true,
}

// operatorGET lists reads that expose packet contents or capture control and
// therefore need more than viewer.
var operatorGET = map[string]bool{
	"GET /api/v1/vms/{node}/capture/ws":          true,
	"GET /api/v1/capture/artifacts/{id}":         true,
	"GET /api/v1/capture/artifacts/{id}/context": true,
}

// viewerPOST lists POSTs that compute an answer without changing state.
var viewerPOST = map[string]bool{
	"POST /api/v1/policies/plan":                 true,
	"POST /api/v1/policies/simulate":             true,
	"POST /api/v1/policies/build":                true,
	"POST /api/v1/watchlist/match":               true,
	"POST /api/v1/intel/preview":                 true,
	"POST /api/v1/ebpf/deny/preview":             true,
	"POST /api/v1/ebpf/deny/preview-history":     true,
	"POST /api/v1/ebpf/scope/preview":            true,
	"POST /api/v1/ebpf/netpol/default-deny/plan": true,
	"POST /api/v1/investigate/connection":        true,
}

// requiredRole is the minimum role for the request's matched route.
func requiredRole(r *http.Request) oidcauth.Role {
	pattern := r.Pattern
	if pattern == "" {
		pattern = r.Method + " " + r.URL.Path
	}
	switch {
	case adminOnly[pattern]:
		return oidcauth.RoleAdmin
	case operatorGET[pattern]:
		return oidcauth.RoleOperator
	case viewerPOST[pattern]:
		return oidcauth.RoleViewer
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return oidcauth.RoleViewer
	default:
		return oidcauth.RoleOperator
	}
}

// principal is the authenticated caller of a request.
type principal struct {
	kind string // "apikey", "chatops", "oidc", "service"
	name string // audit identity; meaningful for "oidc" and "service"
	role oidcauth.Role
	// Scopes: empty means unrestricted on that dimension.
	Namespaces []string
	Clusters   []string
	Tenants    []string
}

type principalKey struct{}

func withPrincipal(ctx context.Context, p principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func principalFrom(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(principalKey{}).(principal)
	return p, ok
}

// verifiedActor returns the audit identity for callers Netra itself
// authenticated as a person. The X-Netra-Actor header is client-supplied and
// unverified, so it must never override this.
func verifiedActor(r *http.Request) (string, bool) {
	if p, ok := principalFrom(r.Context()); ok && (p.kind == "oidc" || p.kind == "service") {
		return p.name, true
	}
	return "", false
}

type authResult int

const (
	authOK          authResult = iota
	authDenied                 // 401: no or invalid credentials
	authForbidden              // 403: valid token, no Netra role
	authUnavailable            // 503: IdP keys unreachable
)

// authenticate resolves the caller from the bearer credential. Static keys
// are compared first, in constant time; scoped service credentials next;
// only a token shaped like a JWT is sent to the OIDC verifier.
func (s *Server) authenticate(r *http.Request) (principal, authResult) {
	tok := bearer(r)
	if tok == "" && s.sessionValid(r) {
		tok = s.apiKey
	}
	if s.apiKey != "" && secureEq(tok, s.apiKey) {
		return principal{kind: "apikey", role: oidcauth.RoleAdmin}, authOK
	}
	if s.chatopsAPIKey != "" && secureEq(tok, s.chatopsAPIKey) {
		return principal{kind: "chatops", role: oidcauth.RoleAdmin}, authOK
	}
	if p, ok := s.matchServiceCred(tok); ok {
		return p, authOK
	}
	if s.oidc == nil || !oidcauth.Looks(tok) {
		return principal{}, authDenied
	}
	id, err := s.oidc.Verify(r.Context(), tok)
	switch {
	case err == nil:
		return principal{
			kind: "oidc", name: id.Name, role: id.Role,
			Namespaces: id.Namespaces, Clusters: id.Clusters, Tenants: id.Tenants,
		}, authOK
	case errors.Is(err, oidcauth.ErrNoRole):
		return principal{}, authForbidden
	case errors.Is(err, oidcauth.ErrKeysUnavailable):
		return principal{}, authUnavailable
	default:
		// The reason (expired, wrong audience, bad signature) stays in the
		// log; the client only learns that the token was not accepted.
		if s.log != nil {
			s.log.Debug("oidc token rejected", "error", err)
		}
		return principal{}, authDenied
	}
}

// authRequired reports whether any credential is needed at all. With no API
// key, no OIDC and no service credentials the server is in explicit
// development mode and open.
func (s *Server) authRequired() bool {
	return s.apiKey != "" || s.oidc != nil || len(s.serviceCreds) > 0
}

// WithOIDC enables OIDC/JWT bearer authentication alongside the static keys.
func (s *Server) WithOIDC(v *oidcauth.Verifier) *Server {
	s.oidc = v
	return s
}

// metricsAuth guards /metrics only when NETRA_METRICS_TOKEN is set, so
// existing unauthenticated scrapes keep working until an operator opts in.
// Accepted: the dedicated token, or any valid API credential with at least
// viewer. The token is read from the Authorization header only, never from a
// query string that scrapers and proxies would log.
func (s *Server) metricsAuth(next http.Handler) http.Handler {
	if s.metricsToken == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hdr := headerBearer(r); hdr != "" {
			if secureEq(hdr, s.metricsToken) {
				next.ServeHTTP(w, r)
				return
			}
			if p, res := s.authenticate(r); res == authOK && p.role.AtLeast(oidcauth.RoleViewer) {
				next.ServeHTTP(w, r)
				return
			}
		}
		s.metricsData.authFailures.Add(1)
		w.Header().Set("WWW-Authenticate", `Bearer realm="netra-metrics"`)
		errorJSON(w, http.StatusUnauthorized, "metrics token required")
	})
}

func headerBearer(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return ""
}

// whoami reports the caller's resolved identity and role.
func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"authRequired": s.authRequired(), "oidcEnabled": s.oidc != nil}
	if p, ok := principalFrom(r.Context()); ok {
		out["kind"], out["role"] = p.kind, p.role.String()
		if p.name != "" {
			out["identity"] = p.name
		}
		if len(p.Namespaces) > 0 {
			out["namespaces"] = p.Namespaces
		}
		if len(p.Clusters) > 0 {
			out["clusters"] = p.Clusters
		}
		if len(p.Tenants) > 0 {
			out["tenants"] = p.Tenants
		}
		out["scoped"] = !p.Unrestricted()
	} else {
		out["kind"], out["role"] = "anonymous", oidcauth.RoleAdmin.String()
		out["scoped"] = false
	}
	writeJSON(w, http.StatusOK, out)
}
