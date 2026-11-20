// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package oidcauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testAud = "netra"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// fakeIdP serves OIDC discovery and a JWKS, counts requests, and can publish
// different keys over time or go down.
type fakeIdP struct {
	*httptest.Server
	mu        sync.Mutex
	keys      []jwk
	down      bool
	issuerOvr string // when set, discovery reports this issuer instead
	discHits  atomic.Int32
	jwksHits  atomic.Int32
}

func newIdP(t *testing.T) *fakeIdP {
	t.Helper()
	idp := &fakeIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		idp.discHits.Add(1)
		idp.mu.Lock()
		down, ovr := idp.down, idp.issuerOvr
		idp.mu.Unlock()
		if down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		iss := idp.URL
		if ovr != "" {
			iss = ovr
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "jwks_uri": idp.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		idp.jwksHits.Add(1)
		idp.mu.Lock()
		down, keys := idp.down, append([]jwk(nil), idp.keys...)
		idp.mu.Unlock()
		if down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	idp.Server = httptest.NewServer(mux)
	t.Cleanup(idp.Close)
	return idp
}

func (i *fakeIdP) publish(keys ...jwk) { i.mu.Lock(); i.keys = keys; i.mu.Unlock() }
func (i *fakeIdP) setDown(d bool)      { i.mu.Lock(); i.down = d; i.mu.Unlock() }

func b64(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.Bytes()) }

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rsaJWK(k *rsa.PrivateKey, kid string) jwk {
	return jwk{Kty: "RSA", Kid: kid, Use: "sig", N: b64(k.N), E: b64(big.NewInt(int64(k.E)))}
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ecJWK(k *ecdsa.PrivateKey, kid string) jwk {
	pt, err := k.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		panic(err)
	}
	x, y := pt[1:33], pt[33:]
	return jwk{Kty: "EC", Kid: kid, Use: "sig", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(x), Y: base64.RawURLEncoding.EncodeToString(y)}
}

type env struct {
	t   *testing.T
	idp *fakeIdP
	clk *clock
	v   *Verifier
}

func newEnv(t *testing.T, mut func(*Config)) *env {
	t.Helper()
	idp := newIdP(t)
	clk := &clock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
	cfg := Config{
		Issuer: idp.URL, Audience: testAud, AllowInsecureHTTP: true,
		Now: clk.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		MinRefresh: 15 * time.Second, JWKSTTL: 10 * time.Minute,
	}
	if mut != nil {
		mut(&cfg)
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &env{t: t, idp: idp, clk: clk, v: v}
}

func (e *env) claims(extra map[string]any) jwt.MapClaims {
	c := jwt.MapClaims{
		"iss": e.idp.URL, "aud": testAud, "sub": "user-1", "email": "ada@example.com",
		"exp": e.clk.Now().Add(time.Hour).Unix(), "iat": e.clk.Now().Unix(),
		"roles": []string{"operator"},
	}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

func sign(t *testing.T, method jwt.SigningMethod, key any, kid string, c jwt.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, c)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (e *env) verify(raw string) (*Identity, error) {
	return e.v.Verify(context.Background(), raw)
}

func TestVerifyValidRS256AndES256(t *testing.T) {
	e := newEnv(t, nil)
	rk, ek := rsaKey(t, 2048), ecKey(t)
	e.idp.publish(rsaJWK(rk, "rsa-1"), ecJWK(ek, "ec-1"))

	id, err := e.verify(sign(t, jwt.SigningMethodRS256, rk, "rsa-1", e.claims(nil)))
	if err != nil {
		t.Fatalf("RS256: %v", err)
	}
	if id.Role != RoleOperator || id.Subject != "user-1" || id.Name != "oidc:ada@example.com" {
		t.Fatalf("identity = %+v", id)
	}
	if !id.Expires.After(e.clk.Now()) {
		t.Fatalf("Expires not set: %v", id.Expires)
	}
	if _, err := e.verify(sign(t, jwt.SigningMethodES256, ek, "ec-1", e.claims(nil))); err != nil {
		t.Fatalf("ES256: %v", err)
	}
}

func TestVerifyRejectsBadClaims(t *testing.T) {
	e := newEnv(t, nil)
	rk := rsaKey(t, 2048)
	e.idp.publish(rsaJWK(rk, "k"))
	now := e.clk.Now()

	cases := map[string]jwt.MapClaims{
		"expired":        e.claims(map[string]any{"exp": now.Add(-time.Hour).Unix()}),
		"no exp":         e.claims(map[string]any{"exp": nil}),
		"not yet valid":  e.claims(map[string]any{"nbf": now.Add(time.Hour).Unix()}),
		"wrong issuer":   e.claims(map[string]any{"iss": "https://evil.example"}),
		"no issuer":      e.claims(map[string]any{"iss": nil}),
		"wrong audience": e.claims(map[string]any{"aud": "some-other-app"}),
		"no audience":    e.claims(map[string]any{"aud": nil}),
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := e.verify(sign(t, jwt.SigningMethodRS256, rk, "k", c))
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("err = %v, want ErrInvalidToken", err)
			}
		})
	}

	// aud as an array containing ours is fine; one without is not.
	if _, err := e.verify(sign(t, jwt.SigningMethodRS256, rk, "k", e.claims(map[string]any{"aud": []string{"x", testAud}}))); err != nil {
		t.Fatalf("aud array containing ours should pass: %v", err)
	}
	if _, err := e.verify(sign(t, jwt.SigningMethodRS256, rk, "k", e.claims(map[string]any{"aud": []string{"x", "y"}}))); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("aud array without ours must fail, got %v", err)
	}

	// Small clock skew is tolerated, large is not.
	if _, err := e.verify(sign(t, jwt.SigningMethodRS256, rk, "k", e.claims(map[string]any{"exp": now.Add(-30 * time.Second).Unix()}))); err != nil {
		t.Fatalf("30s past exp is inside the 60s leeway: %v", err)
	}
}

func TestVerifyRejectsAlgorithmAttacks(t *testing.T) {
	e := newEnv(t, nil)
	rk := rsaKey(t, 2048)
	e.idp.publish(rsaJWK(rk, "k"))

	t.Run("alg none", func(t *testing.T) {
		raw := sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, "k", e.claims(nil))
		if _, err := e.verify(raw); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("alg=none must be rejected, got %v", err)
		}
	})

	// Algorithm confusion: sign HS256 using the RSA public key's bytes as the
	// HMAC secret, hoping the verifier treats the key as a shared secret.
	t.Run("HS256 with public key as secret", func(t *testing.T) {
		secret := []byte(b64(rk.N))
		raw := sign(t, jwt.SigningMethodHS256, secret, "k", e.claims(nil))
		if _, err := e.verify(raw); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("HS256 must be rejected, got %v", err)
		}
	})

	t.Run("tampered payload keeps old signature", func(t *testing.T) {
		raw := sign(t, jwt.SigningMethodRS256, rk, "k", e.claims(map[string]any{"roles": []string{"viewer"}}))
		parts := strings.Split(raw, ".")
		forged, _ := json.Marshal(e.claims(map[string]any{"roles": []string{"admin"}}))
		parts[1] = base64.RawURLEncoding.EncodeToString(forged)
		if _, err := e.verify(strings.Join(parts, ".")); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("tampered token must be rejected, got %v", err)
		}
	})

	t.Run("signed by a key the IdP does not publish", func(t *testing.T) {
		other := rsaKey(t, 2048)
		raw := sign(t, jwt.SigningMethodRS256, other, "k", e.claims(nil))
		if _, err := e.verify(raw); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("foreign-key token must be rejected, got %v", err)
		}
	})

	t.Run("JWK alg pins the token alg", func(t *testing.T) {
		pinned := rsaJWK(rk, "pinned")
		pinned.Alg = "RS512"
		e.idp.publish(pinned)
		e.clk.Advance(time.Minute)
		if _, err := e.verify(sign(t, jwt.SigningMethodRS256, rk, "pinned", e.claims(nil))); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("RS256 token against an RS512-pinned key must fail, got %v", err)
		}
		if _, err := e.verify(sign(t, jwt.SigningMethodRS512, rk, "pinned", e.claims(nil))); err != nil {
			t.Fatalf("RS512 token should pass: %v", err)
		}
	})
}

func TestVerifyGarbageAndOversize(t *testing.T) {
	e := newEnv(t, nil)
	e.idp.publish(rsaJWK(rsaKey(t, 2048), "k"))
	for name, raw := range map[string]string{
		"empty":    "",
		"garbage":  "not-a-jwt",
		"two dots": "a.b.c",
		"oversize": strings.Repeat("a", maxTokenBytes+1),
	} {
		if _, err := e.verify(raw); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("%s: err = %v, want ErrInvalidToken", name, err)
		}
	}
	if e.idp.jwksHits.Load() != 0 {
		t.Fatal("malformed tokens must not trigger a JWKS fetch")
	}
}

func TestLooks(t *testing.T) {
	if !Looks("a.b.c") || Looks("static-api-key") || Looks("a.b") || Looks("a.b.c.d") || Looks("a. b.c") {
		t.Fatal("Looks misclassified")
	}
}

func TestRoleMapping(t *testing.T) {
	rk := rsaKey(t, 2048)
	run := func(t *testing.T, mut func(*Config), extra map[string]any) (*Identity, error) {
		e := newEnv(t, mut)
		e.idp.publish(rsaJWK(rk, "k"))
		return e.verify(sign(t, jwt.SigningMethodRS256, rk, "k", e.claims(extra)))
	}

	t.Run("highest role wins", func(t *testing.T) {
		id, err := run(t, nil, map[string]any{"roles": []string{"viewer", "admin", "operator"}})
		if err != nil || id.Role != RoleAdmin {
			t.Fatalf("role = %v, err = %v", id, err)
		}
	})
	t.Run("single string claim", func(t *testing.T) {
		id, err := run(t, nil, map[string]any{"roles": "viewer"})
		if err != nil || id.Role != RoleViewer {
			t.Fatalf("role = %v, err = %v", id, err)
		}
	})
	t.Run("group mapping", func(t *testing.T) {
		m, _ := ParseRoleMap("netra-admins=admin,sre=operator")
		id, err := run(t, func(c *Config) { c.RolesClaim = "groups"; c.RoleMap = m },
			map[string]any{"groups": []string{"everyone", "sre"}, "roles": nil})
		if err != nil || id.Role != RoleOperator {
			t.Fatalf("role = %v, err = %v", id, err)
		}
	})
	t.Run("nested dotted path", func(t *testing.T) {
		id, err := run(t, func(c *Config) { c.RolesClaim = "realm_access.roles" },
			map[string]any{"roles": nil, "realm_access": map[string]any{"roles": []string{"admin"}}})
		if err != nil || id.Role != RoleAdmin {
			t.Fatalf("role = %v, err = %v", id, err)
		}
	})
	t.Run("claim name that itself contains dots", func(t *testing.T) {
		id, err := run(t, func(c *Config) { c.RolesClaim = "https://netra.example/roles" },
			map[string]any{"roles": nil, "https://netra.example/roles": []string{"viewer"}})
		if err != nil || id.Role != RoleViewer {
			t.Fatalf("role = %v, err = %v", id, err)
		}
	})
	t.Run("no matching role is forbidden not unauthorized", func(t *testing.T) {
		_, err := run(t, nil, map[string]any{"roles": []string{"random-group"}})
		if !errors.Is(err, ErrNoRole) {
			t.Fatalf("err = %v, want ErrNoRole", err)
		}
	})
	t.Run("missing roles claim is forbidden", func(t *testing.T) {
		if _, err := run(t, nil, map[string]any{"roles": nil}); !errors.Is(err, ErrNoRole) {
			t.Fatalf("err = %v, want ErrNoRole", err)
		}
	})
	t.Run("default role", func(t *testing.T) {
		id, err := run(t, func(c *Config) { c.DefaultRole = RoleViewer }, map[string]any{"roles": []string{"random"}})
		if err != nil || id.Role != RoleViewer {
			t.Fatalf("role = %v, err = %v", id, err)
		}
	})
	t.Run("role values are case sensitive", func(t *testing.T) {
		if _, err := run(t, nil, map[string]any{"roles": []string{"Admin"}}); !errors.Is(err, ErrNoRole) {
			t.Fatalf("err = %v, want ErrNoRole", err)
		}
	})
	t.Run("identity falls back to sub and is sanitized", func(t *testing.T) {
		id, err := run(t, nil, map[string]any{"email": nil, "sub": "abc\n123"})
		if err != nil || id.Name != "oidc:abc123" {
			t.Fatalf("identity = %v, err = %v", id, err)
		}
	})
}

func TestKeyRotationRefetchesOnUnknownKid(t *testing.T) {
	e := newEnv(t, nil)
	old, fresh := rsaKey(t, 2048), rsaKey(t, 2048)
	e.idp.publish(rsaJWK(old, "old"))
	if _, err := e.verify(sign(t, jwt.SigningMethodRS256, old, "old", e.claims(nil))); err != nil {
		t.Fatal(err)
	}
	if got := e.idp.jwksHits.Load(); got != 1 {
		t.Fatalf("jwks hits = %d, want 1", got)
	}

	// IdP rotates: publishes only the new key. Within MinRefresh we do not
	// chase it (rate limit); after it, the unknown kid triggers one refetch.
	e.idp.publish(rsaJWK(fresh, "new"))
	tok := sign(t, jwt.SigningMethodRS256, fresh, "new", e.claims(nil))
	if _, err := e.verify(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("inside MinRefresh the rotated key is not fetched yet, got %v", err)
	}
	e.clk.Advance(20 * time.Second)
	if _, err := e.verify(tok); err != nil {
		t.Fatalf("after MinRefresh the new key must be picked up: %v", err)
	}
	if got := e.idp.jwksHits.Load(); got != 2 {
		t.Fatalf("jwks hits = %d, want 2", got)
	}
}

// A flood of tokens naming random key IDs must not become a flood against
// the IdP.
func TestForgedKidsAreRateLimitedAgainstTheIdP(t *testing.T) {
	e := newEnv(t, nil)
	rk := rsaKey(t, 2048)
	e.idp.publish(rsaJWK(rk, "real"))
	if _, err := e.verify(sign(t, jwt.SigningMethodRS256, rk, "real", e.claims(nil))); err != nil {
		t.Fatal(err)
	}
	before := e.idp.jwksHits.Load()
	for i := 0; i < 200; i++ {
		_, _ = e.verify(sign(t, jwt.SigningMethodRS256, rk, "forged-"+string(rune('a'+i%26)), e.claims(nil)))
	}
	if extra := e.idp.jwksHits.Load() - before; extra > 1 {
		t.Fatalf("200 forged kids caused %d extra IdP fetches, want at most 1", extra)
	}
}

func TestKeysExpireAndRefreshButStaleSurvivesIdPOutage(t *testing.T) {
	e := newEnv(t, nil)
	rk := rsaKey(t, 2048)
	e.idp.publish(rsaJWK(rk, "k"))
	tok := func() string { return sign(t, jwt.SigningMethodRS256, rk, "k", e.claims(nil)) }
	if _, err := e.verify(tok()); err != nil {
		t.Fatal(err)
	}

	e.clk.Advance(11 * time.Minute) // TTL passed
	if _, err := e.verify(tok()); err != nil {
		t.Fatal(err)
	}
	if got := e.idp.jwksHits.Load(); got != 2 {
		t.Fatalf("expected a TTL refresh, jwks hits = %d", got)
	}

	// IdP down at the next refresh: keep serving the cached key.
	e.idp.setDown(true)
	e.clk.Advance(11 * time.Minute)
	if _, err := e.verify(tok()); err != nil {
		t.Fatalf("stale keys must survive an IdP outage: %v", err)
	}
}

func TestIdPDownAtStartIsUnavailableNotUnauthorizedAndBacksOff(t *testing.T) {
	e := newEnv(t, nil)
	e.idp.setDown(true)
	rk := rsaKey(t, 2048)
	tok := sign(t, jwt.SigningMethodRS256, rk, "k", e.claims(nil))

	for i := 0; i < 50; i++ {
		if _, err := e.verify(tok); !errors.Is(err, ErrKeysUnavailable) {
			t.Fatalf("err = %v, want ErrKeysUnavailable", err)
		}
	}
	if got := e.idp.discHits.Load() + e.idp.jwksHits.Load(); got != 1 {
		t.Fatalf("50 requests hit the down IdP %d times, want 1 (back-off)", got)
	}

	// Recovery: once MinRefresh has passed and the IdP is back, it works.
	e.idp.setDown(false)
	e.idp.publish(rsaJWK(rk, "k"))
	e.clk.Advance(20 * time.Second)
	if _, err := e.verify(tok); err != nil {
		t.Fatalf("should recover once the IdP is back: %v", err)
	}
}

func TestDiscoveryMustNameTheConfiguredIssuer(t *testing.T) {
	e := newEnv(t, nil)
	rk := rsaKey(t, 2048)
	e.idp.publish(rsaJWK(rk, "k"))
	e.idp.mu.Lock()
	e.idp.issuerOvr = "https://someone-else.example"
	e.idp.mu.Unlock()
	if _, err := e.verify(sign(t, jwt.SigningMethodRS256, rk, "k", e.claims(nil))); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("mismatched discovery issuer must yield no keys, got %v", err)
	}
	if e.idp.jwksHits.Load() != 0 {
		t.Fatal("JWKS must not be fetched from an unverified discovery document")
	}
}

func TestWeakAndUnusableKeysAreSkipped(t *testing.T) {
	e := newEnv(t, nil)
	weak, good := rsaKey(t, 1024), rsaKey(t, 2048)
	enc := rsaJWK(rsaKey(t, 2048), "enc")
	enc.Use = "enc"
	e.idp.publish(rsaJWK(weak, "weak"), enc, jwk{Kty: "oct", Kid: "sym"}, rsaJWK(good, "good"))

	if _, err := e.verify(sign(t, jwt.SigningMethodRS256, good, "good", e.claims(nil))); err != nil {
		t.Fatalf("good key should still work: %v", err)
	}
	for _, kid := range []string{"weak", "enc", "sym"} {
		e.clk.Advance(time.Minute)
		if _, err := e.verify(sign(t, jwt.SigningMethodRS256, weak, kid, e.claims(nil))); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("kid %q must not verify, got %v", kid, err)
		}
	}
}

func TestEllipticCurvePointIsValidated(t *testing.T) {
	bad := jwk{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString([]byte{1}), Y: base64.RawURLEncoding.EncodeToString([]byte{2})}
	if _, err := bad.public(); err == nil {
		t.Fatal("an off-curve point must be rejected")
	}
	if _, err := (jwk{Kty: "EC", Crv: "secp256k1", X: "AQ", Y: "Ag"}).public(); err == nil {
		t.Fatal("unsupported curve must be rejected")
	}
}

func TestKidlessTokenOnlyWithASingleKey(t *testing.T) {
	e := newEnv(t, nil)
	a, b := rsaKey(t, 2048), rsaKey(t, 2048)
	e.idp.publish(rsaJWK(a, "a"))
	if _, err := e.verify(sign(t, jwt.SigningMethodRS256, a, "", e.claims(nil))); err != nil {
		t.Fatalf("kid-less token with one published key should verify: %v", err)
	}
	e.idp.publish(rsaJWK(a, "a"), rsaJWK(b, "b"))
	e.clk.Advance(11 * time.Minute)
	if _, err := e.verify(sign(t, jwt.SigningMethodRS256, a, "", e.claims(nil))); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("kid-less token is ambiguous with two keys, got %v", err)
	}
}

func TestConcurrentVerifyFetchesKeysOnce(t *testing.T) {
	e := newEnv(t, nil)
	rk := rsaKey(t, 2048)
	e.idp.publish(rsaJWK(rk, "k"))
	tok := sign(t, jwt.SigningMethodRS256, rk, "k", e.claims(nil))

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.verify(tok); err != nil {
				t.Errorf("verify: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := e.idp.jwksHits.Load(); got != 1 {
		t.Fatalf("32 concurrent first requests caused %d JWKS fetches, want 1", got)
	}
}

func TestExplicitJWKSURLSkipsDiscovery(t *testing.T) {
	idp := newIdP(t)
	rk := rsaKey(t, 2048)
	idp.publish(rsaJWK(rk, "k"))
	clk := &clock{t: time.Now()}
	v, err := New(Config{Issuer: "https://issuer.example", Audience: testAud, JWKSURL: idp.URL + "/jwks",
		AllowInsecureHTTP: true, Now: clk.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	c := jwt.MapClaims{"iss": "https://issuer.example", "aud": testAud, "sub": "s", "exp": clk.Now().Add(time.Hour).Unix(), "roles": "admin"}
	if _, err := v.Verify(context.Background(), sign(t, jwt.SigningMethodRS256, rk, "k", c)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if idp.discHits.Load() != 0 {
		t.Fatal("discovery must be skipped when JWKSURL is set")
	}
}

func TestConfigValidation(t *testing.T) {
	cases := map[string]Config{
		"no issuer":          {Audience: "a"},
		"no audience":        {Issuer: "https://i.example"},
		"http issuer":        {Issuer: "http://i.example", Audience: "a"},
		"http jwks":          {Issuer: "https://i.example", Audience: "a", JWKSURL: "http://i.example/jwks"},
		"non-http issuer":    {Issuer: "ftp://i.example", Audience: "a"},
		"issuer only spaces": {Issuer: "   ", Audience: "a"},
	}
	for name, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New should fail", name)
		}
	}
	if _, err := New(Config{Issuer: "https://i.example", Audience: "a"}); err != nil {
		t.Fatalf("valid https config rejected: %v", err)
	}
}

func TestParseRoleAndRoleMap(t *testing.T) {
	for in, want := range map[string]Role{"viewer": RoleViewer, "OPERATOR": RoleOperator, " admin ": RoleAdmin, "": RoleNone, "none": RoleNone} {
		if got, err := ParseRole(in); err != nil || got != want {
			t.Errorf("ParseRole(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseRole("root"); err == nil {
		t.Error("unknown role must fail")
	}
	m, err := ParseRoleMap(" a = admin , b=viewer,, ")
	if err != nil || len(m) != 2 || m["a"] != RoleAdmin || m["b"] != RoleViewer {
		t.Fatalf("map = %v, err = %v", m, err)
	}
	for _, bad := range []string{"novalue", "=admin", "x=root", "x=none"} {
		if _, err := ParseRoleMap(bad); err == nil {
			t.Errorf("ParseRoleMap(%q) should fail", bad)
		}
	}
	if !RoleAdmin.AtLeast(RoleViewer) || RoleViewer.AtLeast(RoleOperator) || RoleNone.AtLeast(RoleViewer) {
		t.Error("AtLeast ordering is wrong")
	}
}
