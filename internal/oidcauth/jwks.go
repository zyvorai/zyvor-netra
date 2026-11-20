// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package oidcauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	maxJWKSBytes = 1 << 20
	minRSABits   = 2048
)

// ErrKeysUnavailable means signing keys could not be obtained from the IdP
// and none are cached. It is transient: the caller should answer 503, not 401.
var ErrKeysUnavailable = errors.New("oidc signing keys unavailable")

// errUnknownKey means the token names a key the IdP does not publish.
var errUnknownKey = errors.New("no signing key matches token")

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type pubKey struct {
	key crypto.PublicKey
	alg string // optional JWK "alg"; when set the token must use it
}

// jwksCache holds the IdP's signing keys. It refetches when the cache ages
// out and when a token names an unknown key (rotation), but never more often
// than minRefresh — so a flood of forged key IDs cannot turn Netra into an
// amplifier against the IdP. A failed refresh keeps serving the last good
// keys.
type jwksCache struct {
	issuer     string
	jwksURL    string // "" until resolved via discovery
	insecure   bool
	client     *http.Client
	log        *slog.Logger
	ttl        time.Duration
	minRefresh time.Duration
	now        func() time.Time

	mu          sync.Mutex
	keys        map[string]pubKey
	anon        []pubKey
	fetchedAt   time.Time
	lastAttempt time.Time
	inflight    chan struct{}
}

func (c *jwksCache) lookup(ctx context.Context, kid, alg string) (crypto.PublicKey, error) {
	for attempt := 0; attempt < 2; attempt++ {
		c.mu.Lock()
		now := c.now()
		empty := len(c.keys) == 0 && len(c.anon) == 0
		expired := !c.fetchedAt.IsZero() && now.Sub(c.fetchedAt) > c.ttl
		key, found := c.pickLocked(kid, alg)
		mayRefresh := c.lastAttempt.IsZero() || now.Sub(c.lastAttempt) >= c.minRefresh

		if found && !expired {
			c.mu.Unlock()
			return key, nil
		}
		if c.inflight != nil { // someone is already fetching; wait for them
			wait := c.inflight
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if !mayRefresh {
			c.mu.Unlock()
			switch {
			case found: // expired but refresh is rate limited: stale beats nothing
				return key, nil
			case empty:
				return nil, ErrKeysUnavailable
			default:
				return nil, errUnknownKey
			}
		}
		done := make(chan struct{})
		c.inflight = done
		c.lastAttempt = now
		c.mu.Unlock()

		keys, anon, err := c.fetch(ctx)

		c.mu.Lock()
		c.inflight = nil
		if err == nil {
			c.keys, c.anon, c.fetchedAt = keys, anon, c.now()
		} else {
			c.log.Warn("oidc jwks refresh failed", "error", err, "haveCachedKeys", !empty)
		}
		close(done)
		key, found = c.pickLocked(kid, alg)
		empty = len(c.keys) == 0 && len(c.anon) == 0
		c.mu.Unlock()

		switch {
		case found:
			return key, nil
		case empty:
			return nil, ErrKeysUnavailable
		default:
			return nil, errUnknownKey
		}
	}
	return nil, ErrKeysUnavailable
}

// pickLocked selects the verification key. A token without a kid is only
// accepted when exactly one key is published, so it can never be ambiguous.
func (c *jwksCache) pickLocked(kid, alg string) (crypto.PublicKey, bool) {
	var k pubKey
	switch {
	case kid != "":
		got, ok := c.keys[kid]
		if !ok {
			return nil, false
		}
		k = got
	case len(c.keys)+len(c.anon) == 1:
		if len(c.anon) == 1 {
			k = c.anon[0]
		} else {
			for _, v := range c.keys {
				k = v
			}
		}
	default:
		return nil, false
	}
	if k.alg != "" && k.alg != alg {
		return nil, false
	}
	return k.key, true
}

func (c *jwksCache) fetch(ctx context.Context) (map[string]pubKey, []pubKey, error) {
	url, err := c.resolveURL(ctx)
	if err != nil {
		return nil, nil, err
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := c.getJSON(ctx, url, &doc); err != nil {
		return nil, nil, err
	}
	keys := map[string]pubKey{}
	var anon []pubKey
	for _, j := range doc.Keys {
		if j.Use != "" && j.Use != "sig" {
			continue
		}
		pk, err := j.public()
		if err != nil {
			c.log.Warn("oidc jwks: skipping unusable key", "kid", j.Kid, "kty", j.Kty, "error", err)
			continue
		}
		p := pubKey{key: pk, alg: j.Alg}
		if j.Kid == "" {
			anon = append(anon, p)
		} else {
			keys[j.Kid] = p
		}
	}
	if len(keys)+len(anon) == 0 {
		return nil, nil, errors.New("jwks contains no usable signing keys")
	}
	return keys, anon, nil
}

// resolveURL returns the JWKS URL, discovering it from the issuer once. The
// discovery document must name the same issuer we were configured with, so a
// redirect or a hostile response cannot substitute another IdP's keys.
func (c *jwksCache) resolveURL(ctx context.Context) (string, error) {
	c.mu.Lock()
	u := c.jwksURL
	c.mu.Unlock()
	if u != "" {
		return u, nil
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	disc := strings.TrimRight(c.issuer, "/") + "/.well-known/openid-configuration"
	if err := c.getJSON(ctx, disc, &doc); err != nil {
		return "", fmt.Errorf("oidc discovery: %w", err)
	}
	if doc.Issuer != c.issuer {
		return "", fmt.Errorf("oidc discovery: issuer %q does not match configured %q", doc.Issuer, c.issuer)
	}
	if doc.JWKSURI == "" {
		return "", errors.New("oidc discovery: no jwks_uri")
	}
	if err := checkScheme(doc.JWKSURI, c.insecure); err != nil {
		return "", fmt.Errorf("oidc discovery jwks_uri: %w", err)
	}
	c.mu.Lock()
	c.jwksURL = doc.JWKSURI
	c.mu.Unlock()
	return doc.JWKSURI, nil
}

func (c *jwksCache) getJSON(ctx context.Context, url string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(into)
}

func checkScheme(raw string, insecure bool) error {
	switch {
	case strings.HasPrefix(raw, "https://"):
		return nil
	case strings.HasPrefix(raw, "http://") && insecure:
		return nil
	default:
		return fmt.Errorf("%q must be https", raw)
	}
}

func (j jwk) public() (crypto.PublicKey, error) {
	switch j.Kty {
	case "RSA":
		n, err := b64Int(j.N)
		if err != nil {
			return nil, fmt.Errorf("rsa n: %w", err)
		}
		e, err := b64Int(j.E)
		if err != nil {
			return nil, fmt.Errorf("rsa e: %w", err)
		}
		if n.BitLen() < minRSABits {
			return nil, fmt.Errorf("rsa key is %d bits; need at least %d", n.BitLen(), minRSABits)
		}
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return nil, errors.New("rsa exponent out of range")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", j.Crv)
		}
		x, err := b64Int(j.X)
		if err != nil {
			return nil, fmt.Errorf("ec x: %w", err)
		}
		y, err := b64Int(j.Y)
		if err != nil {
			return nil, fmt.Errorf("ec y: %w", err)
		}
		// ParseUncompressedPublicKey validates the point (on the curve, not
		// the point at infinity) as it parses the SEC1 uncompressed encoding.
		size := (curve.Params().BitSize + 7) / 8
		if x.BitLen() > size*8 || y.BitLen() > size*8 {
			return nil, errors.New("ec coordinate too large for curve")
		}
		point := make([]byte, 1+2*size)
		point[0] = 4
		x.FillBytes(point[1 : 1+size])
		y.FillBytes(point[1+size:])
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("ec point is not valid: %w", err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", j.Kty)
	}
}

func b64Int(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("empty")
	}
	return new(big.Int).SetBytes(b), nil
}
