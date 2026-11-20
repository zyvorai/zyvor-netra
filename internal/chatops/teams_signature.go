// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package chatops

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// botFrameworkOpenIDConfigURL is Bot Framework's own published discovery
// document — the same indirection OpenID Connect always uses, so Microsoft
// can rotate jwks_uri (and the signing keys behind it) without Netra
// hardcoding either.
const botFrameworkOpenIDConfigURL = "https://login.botframework.com/v1/.well-known/openidconfiguration"

// botFrameworkIssuer is the fixed "iss" claim every genuine Bot Framework
// token carries, regardless of which bot or tenant sent it.
const botFrameworkIssuer = "https://api.botframework.com"

// jwksCacheTTL bounds how long a fetched JWKS is trusted before a routine
// refresh, independent of the refetch-on-unknown-kid path below that
// handles Microsoft rotating keys between scheduled refreshes.
const jwksCacheTTL = 24 * time.Hour

// TeamsVerifier verifies inbound Bot Framework "Authorization: Bearer <jwt>"
// tokens: RS256 signature against Microsoft's own published JWKS, plus the
// fixed issuer and the configured Microsoft App ID as audience — the JWT
// equivalent of VerifySlackSignature's HMAC check, just a different inbound
// auth shape entirely (see the package doc comment in client.go).
type TeamsVerifier struct {
	appID string
	// openIDConfigURL is overridable so tests can point it at a local JWKS
	// server instead of the real Bot Framework endpoint.
	openIDConfigURL string
	httpClient      *http.Client
	now             func() time.Time

	mu        sync.Mutex
	jwksURI   string
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// NewTeamsVerifier builds a verifier that only ever accepts tokens whose
// "aud" claim equals appID (NETRA_CHATOPS_TEAMS_APP_ID) — the Teams
// equivalent of Slack's signing secret: it gates the route itself, since
// NewTeamsHandler panics without one.
func NewTeamsVerifier(appID string) *TeamsVerifier {
	return &TeamsVerifier{
		appID:           appID,
		openIDConfigURL: botFrameworkOpenIDConfigURL,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		now:             time.Now,
	}
}

// Verify validates tokenString's RS256 signature against the cached JWKS,
// then its iss/aud/exp claims. Unlike VerifySlackSignature there's no
// separate replay window: "exp" is Bot Framework's own short-lived token
// expiry (minutes), which already bounds replay tightly enough.
func (v *TeamsVerifier) Verify(tokenString string) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("chatops: malformed JWT")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("chatops: malformed JWT header: %w", err)
	}
	claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("chatops: malformed JWT claims: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("chatops: malformed JWT signature: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return fmt.Errorf("chatops: malformed JWT header: %w", err)
	}
	// Bot Framework only ever issues RS256; refusing anything else also
	// closes off the classic "alg: none" downgrade.
	if header.Alg != "RS256" {
		return fmt.Errorf("chatops: unsupported JWT alg %q", header.Alg)
	}
	key, err := v.key(header.Kid)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return fmt.Errorf("chatops: JWT signature verification failed: %w", err)
	}
	var claims struct {
		Iss string `json:"iss"`
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(claimsRaw, &claims); err != nil {
		return fmt.Errorf("chatops: malformed JWT claims: %w", err)
	}
	if claims.Iss != botFrameworkIssuer {
		return fmt.Errorf("chatops: unexpected JWT issuer %q", claims.Iss)
	}
	if claims.Aud != v.appID {
		return fmt.Errorf("chatops: unexpected JWT audience %q", claims.Aud)
	}
	if claims.Exp != 0 && v.now().Unix() > claims.Exp {
		return fmt.Errorf("chatops: JWT expired")
	}
	return nil
}

// key returns the RSA public key for kid, using the cached JWKS if it's
// both present and within jwksCacheTTL, and refreshing once otherwise — the
// same "refetch on cache miss" shape that covers Microsoft rotating its
// signing keys without Netra polling the JWKS on every single request.
func (v *TeamsVerifier) key(kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	k, ok := v.keys[kid]
	fresh := v.now().Sub(v.fetchedAt) < jwksCacheTTL
	v.mu.Unlock()
	if ok && fresh {
		return k, nil
	}
	if err := v.refresh(); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	k, ok = v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("chatops: unknown JWT key id %q", kid)
	}
	return k, nil
}

func (v *TeamsVerifier) refresh() error {
	v.mu.Lock()
	uri := v.jwksURI
	v.mu.Unlock()
	if uri == "" {
		var err error
		uri, err = v.fetchJWKSURI()
		if err != nil {
			return err
		}
	}
	keys, err := v.fetchJWKS(uri)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.jwksURI = uri
	v.keys = keys
	v.fetchedAt = v.now()
	v.mu.Unlock()
	return nil
}

func (v *TeamsVerifier) fetchJWKSURI() (string, error) {
	body, err := v.get(v.openIDConfigURL)
	if err != nil {
		return "", err
	}
	var meta struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", fmt.Errorf("chatops: malformed OpenID config: %w", err)
	}
	if meta.JWKSURI == "" {
		return "", fmt.Errorf("chatops: OpenID config has no jwks_uri")
	}
	return meta.JWKSURI, nil
}

func (v *TeamsVerifier) fetchJWKS(uri string) (map[string]*rsa.PublicKey, error) {
	body, err := v.get(uri)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("chatops: malformed JWKS: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
	}
	return keys, nil
}

func (v *TeamsVerifier) get(url string) ([]byte, error) {
	resp, err := v.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("chatops: fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chatops: fetching %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
