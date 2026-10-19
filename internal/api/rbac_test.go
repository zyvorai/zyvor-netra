// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zyvorai/netra/internal/oidcauth"
	"github.com/zyvorai/netra/internal/store"
)

const (
	testAPIKey = "static-admin-key"
	testAud    = "netra"
)

// idp is a minimal OIDC provider: discovery + JWKS for one RSA key.
type idp struct {
	*httptest.Server
	key  *rsa.PrivateKey
	down bool
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{key: k}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		if p.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": p.URL, "jwks_uri": p.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		if p.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		}}})
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

func (p *idp) token(t *testing.T, mut func(jwt.MapClaims)) string {
	t.Helper()
	c := jwt.MapClaims{
		"iss": p.URL, "aud": testAud, "sub": "u1", "email": "ada@example.com",
		"exp": time.Now().Add(time.Hour).Unix(), "roles": []string{"viewer"},
	}
	if mut != nil {
		mut(c)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(p.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (p *idp) role(t *testing.T, role string) string {
	return p.token(t, func(c jwt.MapClaims) { c["roles"] = []string{role} })
}

// authEnv is a fully wired API server: static admin key plus OIDC.
type authEnv struct {
	t   *testing.T
	idp *idp
	h   http.Handler
	srv *Server
}

func newAuthEnv(t *testing.T, oidcOn bool) *authEnv {
	t.Helper()
	t.Setenv("NETRA_API_KEY", testAPIKey)
	t.Setenv("NETRA_AGENT_KEY", "agent-key")
	t.Setenv("NETRA_CHATOPS_API_KEY", "")
	// The exec/logs/vnc routes only exist when the workload console is on
	// (as on the live cluster); without it they are 404 for everyone.
	t.Setenv("NETRA_WORKLOAD_CONSOLE", "true")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &authEnv{t: t, idp: newIDP(t)}
	e.srv = New(log, nil, nil, store.New())
	if oidcOn {
		v, err := oidcauth.New(oidcauth.Config{Issuer: e.idp.URL, Audience: testAud, AllowInsecureHTTP: true, Logger: log})
		if err != nil {
			t.Fatal(err)
		}
		e.srv.WithOIDC(v)
	}
	e.h = e.srv.Handler()
	return e
}

func (e *authEnv) do(method, path, bearer string, body string, hdr map[string]string) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// passed reports that the request got through authn+authz (the handler then
// ran and may answer anything, typically 400 for our empty bodies).
func passed(rec *httptest.ResponseRecorder) bool {
	return rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden && rec.Code != http.StatusServiceUnavailable
}

func TestRBACRoleLadderOnRealRoutes(t *testing.T) {
	e := newAuthEnv(t, true)
	viewer, operator, admin := e.idp.role(t, "viewer"), e.idp.role(t, "operator"), e.idp.role(t, "admin")

	type rt struct {
		method, path string
		min          oidcauth.Role
	}
	// One representative per class, all safe to invoke with nil kube/hubble
	// because denied requests never reach the handler and allowed ones fail
	// body validation first.
	routes := []rt{
		{"GET", "/api/v1/audit", oidcauth.RoleViewer},
		{"GET", "/api/v1/agents", oidcauth.RoleViewer},
		{"POST", "/api/v1/policies/plan", oidcauth.RoleViewer},     // computes, does not change
		{"POST", "/api/v1/ebpf/deny/preview", oidcauth.RoleViewer}, // preview only
		{"POST", "/api/v1/ebpf/deny/preview-history", oidcauth.RoleViewer},
		{"POST", "/api/v1/ebpf/deny", oidcauth.RoleOperator},            // changes enforcement
		{"DELETE", "/api/v1/ebpf/deny/10.0.0.1", oidcauth.RoleOperator}, // changes enforcement
		{"GET", "/api/v1/capture/artifacts/abc", oidcauth.RoleOperator}, // packet contents
		{"PUT", "/api/v1/ebpf/mode", oidcauth.RoleAdmin},                // fleet posture
		{"POST", "/api/v1/policies/lockdown", oidcauth.RoleAdmin},       // cluster lockdown
		{"POST", "/api/v1/features/some-feature", oidcauth.RoleAdmin},   // rewrites deployments
		{"GET", "/api/v1/pods/ns/pod/exec", oidcauth.RoleAdmin},         // shell into a workload
		{"GET", "/api/v1/pods/ns/pod/logs", oidcauth.RoleAdmin},         // may leak secrets
	}
	tokens := []struct {
		name string
		tok  string
		role oidcauth.Role
	}{{"viewer", viewer, oidcauth.RoleViewer}, {"operator", operator, oidcauth.RoleOperator}, {"admin", admin, oidcauth.RoleAdmin}}

	for _, r := range routes {
		for _, tk := range tokens {
			allowed := tk.role.AtLeast(r.min)
			// An allowed console request would reach a handler that needs a
			// real kube client; only its denials are testable here.
			if allowed && (strings.HasSuffix(r.path, "/exec") || strings.HasSuffix(r.path, "/logs")) {
				continue
			}
			rec := e.do(r.method, r.path, tk.tok, "{}", nil)
			if allowed && rec.Code == http.StatusForbidden {
				t.Errorf("%s %s as %s: got 403, should pass authz (needs %s)", r.method, r.path, tk.name, r.min)
			}
			if !allowed {
				if rec.Code != http.StatusForbidden {
					t.Errorf("%s %s as %s: got %d, want 403 (needs %s)", r.method, r.path, tk.name, rec.Code, r.min)
				} else if !strings.Contains(rec.Body.String(), r.min.String()+" required") {
					t.Errorf("%s %s as %s: 403 body should name the needed role: %s", r.method, r.path, tk.name, rec.Body.String())
				}
			}
		}
	}
}

// Exec/logs/console GETs are the sharpest edge: they must not fall to the
// viewer default just because they are GETs.
func TestRBACAdminGETsNeverReachHandlersForLowerRoles(t *testing.T) {
	e := newAuthEnv(t, true)
	for _, path := range []string{"/api/v1/pods/ns/p/exec", "/api/v1/pods/ns/p/logs", "/api/v1/vms/ns/vm/vnc"} {
		for _, role := range []string{"viewer", "operator"} {
			if rec := e.do("GET", path, e.idp.role(t, role), "", nil); rec.Code != http.StatusForbidden {
				t.Errorf("%s as %s: %d, want 403", path, role, rec.Code)
			}
		}
	}
}

func TestStaticKeysRemainFullAdmin(t *testing.T) {
	e := newAuthEnv(t, true)
	for _, path := range []struct{ m, p string }{{"PUT", "/api/v1/ebpf/mode"}, {"POST", "/api/v1/policies/lockdown"}, {"POST", "/api/v1/ebpf/deny"}} {
		if rec := e.do(path.m, path.p, testAPIKey, "{}", nil); !passed(rec) {
			t.Errorf("%s %s with the static API key: %d, must remain admin", path.m, path.p, rec.Code)
		}
	}
	if rec := e.do("GET", "/api/v1/audit", "wrong-key", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong static key: %d, want 401", rec.Code)
	}
}

func TestOIDCFailureModes(t *testing.T) {
	e := newAuthEnv(t, true)
	cases := []struct {
		name string
		tok  string
		want int
	}{
		{"no credential", "", 401},
		{"garbage", "not.a.jwt", 401},
		{"expired", e.idp.token(t, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }), 401},
		{"wrong audience", e.idp.token(t, func(c jwt.MapClaims) { c["aud"] = "other-app" }), 401},
		{"wrong issuer", e.idp.token(t, func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }), 401},
		{"valid token but no netra role", e.idp.token(t, func(c jwt.MapClaims) { c["roles"] = []string{"random"} }), 403},
	}
	for _, tc := range cases {
		if rec := e.do("GET", "/api/v1/audit", tc.tok, "", nil); rec.Code != tc.want {
			t.Errorf("%s: %d, want %d (%s)", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}

	// A token signed by some other key must not verify.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": e.idp.URL, "aud": testAud, "sub": "x", "exp": time.Now().Add(time.Hour).Unix(), "roles": "admin"})
	forged.Header["kid"] = "k1"
	raw, _ := forged.SignedString(other)
	if rec := e.do("PUT", "/api/v1/ebpf/mode", raw, "{}", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("forged admin token: %d, want 401", rec.Code)
	}
}

func TestOIDCOffLeavesJWTsUnauthorized(t *testing.T) {
	e := newAuthEnv(t, false)
	if rec := e.do("GET", "/api/v1/audit", e.idp.role(t, "admin"), "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("JWT with OIDC disabled: %d, want 401", rec.Code)
	}
	if rec := e.do("GET", "/api/v1/audit", testAPIKey, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("static key with OIDC disabled: %d, want 200", rec.Code)
	}
}

func TestIdPOutageIs503NotLogout(t *testing.T) {
	e := newAuthEnv(t, true)
	e.idp.down = true
	if rec := e.do("GET", "/api/v1/audit", e.idp.role(t, "admin"), "", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("IdP down: %d, want 503", rec.Code)
	}
	// The break-glass static key keeps working while the IdP is down.
	if rec := e.do("GET", "/api/v1/audit", testAPIKey, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("static key during IdP outage: %d, want 200", rec.Code)
	}
}

func TestWhoami(t *testing.T) {
	e := newAuthEnv(t, true)
	get := func(tok string) map[string]any {
		rec := e.do("GET", "/api/v1/whoami", tok, "", nil)
		if rec.Code != 200 {
			t.Fatalf("whoami: %d %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	if got := get(e.idp.role(t, "operator")); got["kind"] != "oidc" || got["role"] != "operator" || got["identity"] != "oidc:ada@example.com" {
		t.Fatalf("oidc whoami = %v", got)
	}
	if got := get(testAPIKey); got["kind"] != "apikey" || got["role"] != "admin" {
		t.Fatalf("apikey whoami = %v", got)
	}
	if rec := e.do("GET", "/api/v1/whoami", "", "", nil); rec.Code != 401 {
		t.Fatalf("whoami without credentials: %d", rec.Code)
	}
}

func TestDevModeStaysOpenWithNoKeysAndNoOIDC(t *testing.T) {
	t.Setenv("NETRA_API_KEY", "")
	t.Setenv("NETRA_AGENT_KEY", "")
	h := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, store.New()).Handler()
	req := httptest.NewRequest("GET", "/api/v1/whoami", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || out["kind"] != "anonymous" || out["authRequired"] != false {
		t.Fatalf("dev mode whoami = %d %v", rec.Code, out)
	}
}

// X-Netra-Actor is client-controlled. A verified person's identity must win.
func TestVerifiedActorCannotBeSpoofedByHeader(t *testing.T) {
	e := newAuthEnv(t, true)
	var got string
	probe := e.srv.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = actor(r)
	}))
	call := func(tok string) string {
		got = ""
		req := httptest.NewRequest("GET", "/x", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-Netra-Actor", "root")
		probe.ServeHTTP(httptest.NewRecorder(), req)
		return got
	}
	if a := call(e.idp.role(t, "operator")); a != "oidc:ada@example.com" {
		t.Fatalf("oidc actor = %q, want the verified identity, not the header", a)
	}
	// Static-key callers keep the documented header behaviour (back-compat).
	if a := call(testAPIKey); a != "root" {
		t.Fatalf("api-key actor = %q, want the X-Netra-Actor value", a)
	}
}

func TestDeniedRequestsAreCounted(t *testing.T) {
	e := newAuthEnv(t, true)
	e.do("PUT", "/api/v1/ebpf/mode", e.idp.role(t, "viewer"), "{}", nil)
	e.do("PUT", "/api/v1/ebpf/mode", e.idp.role(t, "operator"), "{}", nil)
	rec := e.do("GET", "/metrics", "", "", nil)
	if !strings.Contains(rec.Body.String(), "netra_rbac_denied_total 2") {
		t.Fatalf("expected netra_rbac_denied_total 2 in metrics, got:\n%s", grep(rec.Body.String(), "rbac"))
	}
}

func TestQueryStringTokenStillWorksForWebSocketStyleClients(t *testing.T) {
	e := newAuthEnv(t, true)
	if rec := e.do("GET", "/api/v1/whoami?token="+e.idp.role(t, "viewer"), "", "", nil); rec.Code != 200 {
		t.Fatalf("?token= JWT: %d", rec.Code)
	}
}

func TestMetricsTokenGate(t *testing.T) {
	t.Run("open by default", func(t *testing.T) {
		e := newAuthEnv(t, true)
		if rec := e.do("GET", "/metrics", "", "", nil); rec.Code != 200 {
			t.Fatalf("/metrics with no token configured: %d, want 200 (unchanged default)", rec.Code)
		}
	})
	t.Run("closed when a token is set", func(t *testing.T) {
		t.Setenv("NETRA_METRICS_TOKEN", "scrape-secret")
		e := newAuthEnv(t, true)
		if rec := e.do("GET", "/metrics", "", "", nil); rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("no credential: %d, want 401 with WWW-Authenticate", rec.Code)
		}
		if rec := e.do("GET", "/metrics", "wrong", "", nil); rec.Code != 401 {
			t.Fatalf("wrong token: %d", rec.Code)
		}
		if rec := e.do("GET", "/metrics", "scrape-secret", "", nil); rec.Code != 200 {
			t.Fatalf("metrics token: %d", rec.Code)
		}
		if rec := e.do("GET", "/metrics", testAPIKey, "", nil); rec.Code != 200 {
			t.Fatalf("admin key should also read metrics: %d", rec.Code)
		}
		if rec := e.do("GET", "/metrics", e.idp.role(t, "viewer"), "", nil); rec.Code != 200 {
			t.Fatalf("viewer JWT should read metrics: %d", rec.Code)
		}
		// A token in the URL is logged by scrapers and proxies: not accepted.
		if rec := e.do("GET", "/metrics?token=scrape-secret", "", "", nil); rec.Code != 401 {
			t.Fatalf("query-string metrics token: %d, want 401", rec.Code)
		}
		// Health endpoints stay open for kubelet probes.
		if rec := e.do("GET", "/healthz", "", "", nil); rec.Code != 200 {
			t.Fatalf("/healthz: %d", rec.Code)
		}
	})
}

func TestAuthOrAgentRouteAcceptsAgentKeyAndViewerJWT(t *testing.T) {
	e := newAuthEnv(t, true)
	const p = "/api/v1/ebpf/config"
	if rec := e.do("GET", p, "", "", map[string]string{"X-Netra-Agent-Key": "agent-key"}); !passed(rec) {
		t.Fatalf("agent key: %d", rec.Code)
	}
	if rec := e.do("GET", p, e.idp.role(t, "viewer"), "", nil); !passed(rec) {
		t.Fatalf("viewer JWT: %d", rec.Code)
	}
	if rec := e.do("GET", p, "", "", nil); rec.Code != 401 {
		t.Fatalf("no credential: %d, want 401", rec.Code)
	}
	if rec := e.do("GET", p, "", "", map[string]string{"X-Netra-Agent-Key": "nope"}); rec.Code != 401 {
		t.Fatalf("wrong agent key: %d, want 401", rec.Code)
	}
}

// --- route-table integrity -------------------------------------------------

var routeRE = regexp.MustCompile(`mux\.Handle(?:Func)?\("([A-Z]+ [^"]+)"`)

func registeredPatterns(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, m := range routeRE.FindAllStringSubmatch(string(src), -1) {
		out[m[1]] = true
	}
	if len(out) < 100 {
		t.Fatalf("parsed only %d routes from server.go; the pattern regexp has rotted", len(out))
	}
	return out
}

// A typo or a renamed route in the role tables would silently downgrade that
// route to the method default. This fails the build instead.
func TestRoleTablesOnlyNameRegisteredRoutes(t *testing.T) {
	routes := registeredPatterns(t)
	for name, table := range map[string]map[string]bool{"adminOnly": adminOnly, "operatorGET": operatorGET, "viewerPOST": viewerPOST} {
		for pat := range table {
			if !routes[pat] {
				t.Errorf("%s lists %q, which is not a registered route (renamed or typo?)", name, pat)
			}
		}
	}
	for pat := range operatorGET {
		if !strings.HasPrefix(pat, "GET ") {
			t.Errorf("operatorGET entry %q is not a GET", pat)
		}
	}
	for pat := range viewerPOST {
		if !strings.HasPrefix(pat, "POST ") {
			t.Errorf("viewerPOST entry %q is not a POST", pat)
		}
	}
	for pat := range adminOnly {
		if operatorGET[pat] || viewerPOST[pat] {
			t.Errorf("%q appears in more than one role table", pat)
		}
	}
}

// Every registered route must resolve to a role, and every state-changing
// route not explicitly relaxed must need at least operator.
func TestEveryMutatingRouteRequiresOperatorOrAbove(t *testing.T) {
	for pat := range registeredPatterns(t) {
		method, path, _ := strings.Cut(pat, " ")
		req := httptest.NewRequest(method, "http://x"+strings.NewReplacer("{", "", "}", "").Replace(path), nil)
		req.Pattern = pat
		need := requiredRole(req)
		switch method {
		case "GET", "HEAD", "OPTIONS":
			if need < oidcauth.RoleViewer {
				t.Errorf("%s resolves to %s", pat, need)
			}
		default:
			if viewerPOST[pat] {
				continue
			}
			if need < oidcauth.RoleOperator {
				t.Errorf("state-changing route %s resolves to %s; it must need operator or admin", pat, need)
			}
		}
	}
}

func TestRequiredRoleDefaultsWhenPatternUnknown(t *testing.T) {
	mk := func(method, path string) *http.Request { return httptest.NewRequest(method, path, nil) }
	if got := requiredRole(mk("GET", "/api/v1/brand-new-read")); got != oidcauth.RoleViewer {
		t.Errorf("unknown GET = %s, want viewer", got)
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if got := requiredRole(mk(m, "/api/v1/brand-new-write")); got != oidcauth.RoleOperator {
			t.Errorf("unknown %s = %s, want operator (safe default for a new mutating route)", m, got)
		}
	}
}

func grep(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func TestSessionCookieAuthenticatesWithoutStoringTheAPIKey(t *testing.T) {
	e := newAuthEnv(t, false)
	bad := e.do("POST", "/api/v1/session", "", `{"token":"nope"}`, nil)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", bad.Code)
	}
	rec := e.do("POST", "/api/v1/session", "", `{"token":"`+testAPIKey+`"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	var sess *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	if sess == nil || !sess.HttpOnly || sess.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie = %#v", sess)
	}
	if strings.Contains(sess.Value, testAPIKey) {
		t.Fatal("session cookie contains the API key")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	req.AddCookie(sess)
	got := httptest.NewRecorder()
	e.h.ServeHTTP(got, req)
	if got.Code != http.StatusOK {
		t.Fatalf("whoami with cookie: %d %s", got.Code, got.Body.String())
	}
	if !strings.Contains(got.Body.String(), `"kind":"apikey"`) {
		t.Fatalf("whoami body = %s", got.Body.String())
	}
}
