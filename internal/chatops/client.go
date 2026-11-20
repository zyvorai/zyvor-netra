// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package chatops supports Slack and Microsoft Teams as inbound ChatOps
// providers. Slack's HMAC-over-body signing (signature.go) and Teams'
// bot-framework JWT auth (teams_signature.go) are different enough shapes
// that each gets its own inbound verification and HTTP handler; both funnel
// into the same provider-agnostic Dispatch/Client below rather than forking
// command logic per provider. Every command is a thin HTTP client of
// netrad's own /api/v1/* endpoints — the same pattern cmd/netractl and
// cmd/netra-mcp already use — never importing internal/api handler
// internals directly.
package chatops

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Client makes outbound calls back into netrad's own HTTP API, the same
// loopback shape any other API client uses, authenticated with a dedicated
// NETRA_CHATOPS_API_KEY distinct from NETRA_API_KEY — matching the existing
// separate-trust-domain convention NETRA_AGENT_KEY already establishes, so
// a compromised Slack app credential can't be replayed as the operator's
// own full-access API key.
type Client struct {
	base       string
	apiKey     string
	httpClient *http.Client
}

// apiPath is the only shape Client.Do will request. Chat commands and
// confirmation buttons contribute the path, so it has to stay on the
// configured controller host and under /api/v1/.
var apiPath = regexp.MustCompile(`^/api/v1/[A-Za-z0-9._/-]+(?:\?[A-Za-z0-9._=&-]+)?$`)

// NewClient builds a Client pointed at targetURL (typically the loopback
// address netrad itself listens on) using apiKey for outbound auth.
// HTTPS uses the system trust store plus NETRA_TLS_CERT when that file is
// set, so the chart's self-signed listener verifies without disabling
// certificate checks.
func NewClient(targetURL, apiKey string) *Client {
	return &Client{
		base:       strings.TrimRight(targetURL, "/"),
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: chatopsTLSConfig()}},
	}
}

func chatopsTLSConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	certFile := strings.TrimSpace(os.Getenv("NETRA_TLS_CERT"))
	if certFile == "" {
		return cfg
	}
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		return cfg
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if pool.AppendCertsFromPEM(pemBytes) {
		cfg.RootCAs = pool
	}
	return cfg
}

// Do performs one call against netrad's own API, setting X-Netra-Actor to
// actor (e.g. "chatops:<slack-user-id>" or "chatops-teams:<teams-user-id>")
// so it lands in the exact same audit trail every other mutation already
// does, with no new audit mechanism needed here at all.
func (c *Client) Do(ctx context.Context, method, path string, body []byte, actor string) ([]byte, int, error) {
	endpoint, err := c.endpoint(path)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	if actor != "" {
		req.Header.Set("X-Netra-Actor", actor)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return out, resp.StatusCode, nil
}

// endpoint pins the request to the configured controller. path may come from
// a chat command (a node name, a lease, or a confirmation payload) and must
// not be able to change the host.
func (c *Client) endpoint(path string) (string, error) {
	if !apiPath.MatchString(path) {
		return "", fmt.Errorf("chatops: refusing path %q", path)
	}
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("chatops: refusing path %q", path)
	}
	base, err := url.Parse(c.base)
	if err != nil || base.Hostname() == "" || base.User != nil {
		return "", fmt.Errorf("chatops: invalid target URL")
	}
	rel, err := url.Parse(path)
	if err != nil || rel.IsAbs() || rel.Host != "" || rel.User != nil {
		return "", fmt.Errorf("chatops: refusing non-relative path %q", path)
	}
	if !strings.HasPrefix(rel.Path, "/api/v1/") {
		return "", fmt.Errorf("chatops: refusing path %q", path)
	}
	base.Path = rel.Path
	base.RawPath = ""
	base.RawQuery = rel.RawQuery
	base.Fragment = ""
	return base.String(), nil
}
