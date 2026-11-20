// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const maxTokenBytes = 16 << 10

var (
	// ErrInvalidToken covers every reason a token is not acceptable:
	// malformed, bad signature, wrong issuer/audience, expired, unsupported
	// algorithm. Callers answer 401 and must not echo the detail.
	ErrInvalidToken = errors.New("invalid token")
	// ErrNoRole means the token is valid but maps to no Netra role: 403.
	ErrNoRole = errors.New("token carries no Netra role")
)

// Only asymmetric algorithms are accepted. HMAC is excluded on purpose: with
// a public JWKS an HS* token would be verified against public key material,
// the classic algorithm-confusion attack.
var allowedAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// Config configures a Verifier.
type Config struct {
	// Issuer is the exact `iss` value tokens must carry. Required.
	Issuer string
	// Audience must appear in a token's `aud`. Required: without it a token
	// minted for any other application of the same IdP would be accepted.
	Audience string
	// JWKSURL overrides discovery via Issuer/.well-known/openid-configuration.
	JWKSURL string
	// RolesClaim is the claim holding roles/groups. A dotted path walks
	// nested objects ("realm_access.roles"); a claim whose own name contains
	// dots ("https://netra/roles") is matched first. Default "roles".
	RolesClaim string
	// RoleMap maps claim values to roles. Nil means the literal values
	// "viewer", "operator" and "admin".
	RoleMap map[string]Role
	// DefaultRole is granted when a valid token maps to nothing. RoleNone
	// (the default) denies such tokens.
	DefaultRole Role
	// IdentityClaim names the claim used as the display identity. Default
	// "email", falling back to "sub".
	IdentityClaim string
	// NamespacesClaim, ClustersClaim, TenantsClaim hold optional scope lists.
	// Empty claim name disables that dimension (caller is unrestricted there).
	NamespacesClaim string
	ClustersClaim   string
	TenantsClaim    string
	// AllowInsecureHTTP permits http:// issuer/JWKS URLs. Development only.
	AllowInsecureHTTP bool

	HTTPClient *http.Client
	Logger     *slog.Logger
	// JWKSTTL is how long fetched keys are trusted (default 10m).
	JWKSTTL time.Duration
	// MinRefresh is the minimum gap between IdP fetches, including forced
	// refreshes for an unknown key ID (default 15s).
	MinRefresh time.Duration
	// ClockSkew is the leeway for exp/nbf (default 60s).
	ClockSkew time.Duration
	Now       func() time.Time
}

// Identity is a verified caller.
type Identity struct {
	Subject string
	// Name is the audit identity, prefixed "oidc:" so it can never collide
	// with the "api:<ip>" actors of key-authenticated callers.
	Name    string
	Role    Role
	Expires time.Time
	// Scopes: empty slice means unrestricted on that dimension.
	Namespaces []string
	Clusters   []string
	Tenants    []string
}

type Verifier struct {
	cfg    Config
	parser *jwt.Parser
	keys   *jwksCache
}

// New validates cfg and returns a Verifier. It does not contact the IdP: a
// briefly unreachable IdP at startup must not stop the controller, so keys
// are fetched lazily on first use.
func New(cfg Config) (*Verifier, error) {
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	cfg.Audience = strings.TrimSpace(cfg.Audience)
	cfg.JWKSURL = strings.TrimSpace(cfg.JWKSURL)
	if cfg.Issuer == "" {
		return nil, errors.New("oidc issuer is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("oidc audience is required (tokens minted for other apps must not be accepted)")
	}
	if err := checkScheme(cfg.Issuer, cfg.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("oidc issuer: %w", err)
	}
	if cfg.JWKSURL != "" {
		if err := checkScheme(cfg.JWKSURL, cfg.AllowInsecureHTTP); err != nil {
			return nil, fmt.Errorf("oidc jwks url: %w", err)
		}
	}
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "roles"
	}
	if cfg.RoleMap == nil {
		cfg.RoleMap = map[string]Role{"viewer": RoleViewer, "operator": RoleOperator, "admin": RoleAdmin}
	}
	if cfg.JWKSTTL <= 0 {
		cfg.JWKSTTL = 10 * time.Minute
	}
	if cfg.MinRefresh <= 0 {
		cfg.MinRefresh = 15 * time.Second
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 60 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &Verifier{
		cfg: cfg,
		parser: jwt.NewParser(
			jwt.WithValidMethods(allowedAlgs),
			jwt.WithIssuer(cfg.Issuer),
			jwt.WithAudience(cfg.Audience),
			jwt.WithExpirationRequired(),
			jwt.WithLeeway(cfg.ClockSkew),
			jwt.WithTimeFunc(cfg.Now),
		),
		keys: &jwksCache{
			issuer:     cfg.Issuer,
			jwksURL:    cfg.JWKSURL,
			insecure:   cfg.AllowInsecureHTTP,
			client:     cfg.HTTPClient,
			log:        cfg.Logger,
			ttl:        cfg.JWKSTTL,
			minRefresh: cfg.MinRefresh,
			now:        cfg.Now,
		},
	}, nil
}

// Looks reports whether s has the shape of a JWT (three dot-separated
// segments), so callers can route static API keys and tokens differently
// without trying to verify a random string.
func Looks(s string) bool { return strings.Count(s, ".") == 2 && !strings.ContainsAny(s, " \t\r\n") }

// Verify checks signature, issuer, audience, expiry and algorithm, then maps
// claims to a role. The returned error is ErrInvalidToken (401),
// ErrNoRole (403) or ErrKeysUnavailable (503), possibly wrapped.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Identity, error) {
	if raw == "" || len(raw) > maxTokenBytes {
		return nil, ErrInvalidToken
	}
	claims := jwt.MapClaims{}
	_, err := v.parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return v.keys.lookup(ctx, kid, t.Method.Alg())
	})
	if err != nil {
		if errors.Is(err, ErrKeysUnavailable) {
			return nil, ErrKeysUnavailable
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	role := v.roleFor(claims)
	if role == RoleNone {
		return nil, ErrNoRole
	}
	sub, _ := claims["sub"].(string)
	id := &Identity{
		Subject:    sub,
		Name:       "oidc:" + v.identity(claims, sub),
		Role:       role,
		Namespaces: scopeValues(claims, v.cfg.NamespacesClaim),
		Clusters:   scopeValues(claims, v.cfg.ClustersClaim),
		Tenants:    scopeValues(claims, v.cfg.TenantsClaim),
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		id.Expires = exp.Time
	}
	return id, nil
}

func scopeValues(claims jwt.MapClaims, claim string) []string {
	claim = strings.TrimSpace(claim)
	if claim == "" {
		return nil
	}
	raw := stringValues(claimValue(claims, claim))
	out := make([]string, 0, len(raw))
	seen := map[string]struct{}{}
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		key := strings.ToLower(s)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	return out
}

func (v *Verifier) identity(claims jwt.MapClaims, sub string) string {
	claim := v.cfg.IdentityClaim
	if claim == "" {
		claim = "email"
	}
	if s, ok := claimValue(claims, claim).(string); ok && strings.TrimSpace(s) != "" {
		return sanitizeIdentity(s)
	}
	return sanitizeIdentity(sub)
}

func (v *Verifier) roleFor(claims jwt.MapClaims) Role {
	best := RoleNone
	for _, val := range stringValues(claimValue(claims, v.cfg.RolesClaim)) {
		if r, ok := v.cfg.RoleMap[val]; ok && r > best {
			best = r
		}
	}
	if best == RoleNone {
		return v.cfg.DefaultRole
	}
	return best
}

// claimValue resolves a claim by exact name first (URL-style names contain
// dots), then as a dotted path through nested objects.
func claimValue(claims map[string]any, name string) any {
	if v, ok := claims[name]; ok {
		return v
	}
	if !strings.Contains(name, ".") {
		return nil
	}
	var cur any = map[string]any(claims)
	for seg := range strings.SplitSeq(name, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if cur, ok = m[seg]; !ok {
			return nil
		}
	}
	return cur
}

func stringValues(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}

// sanitizeIdentity keeps the audit identity to printable, bounded text, since
// it ends up in audit records, syslog/CEF lines and OTLP logs.
func sanitizeIdentity(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 128 {
			break
		}
	}
	return b.String()
}
