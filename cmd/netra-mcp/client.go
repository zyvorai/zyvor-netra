// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// client is a minimal HTTP client for Netra's controller API, mirroring
// cmd/netractl's env-var conventions (NETRA_URL, NETRA_API_KEY,
// NETRA_TLS_INSECURE) so an operator who already runs netractl needs no
// new configuration to also run netra-mcp.
type client struct {
	base       string
	apiKey     string
	actor      string
	httpClient *http.Client
}

func newClient() *client {
	base := strings.TrimRight(env("NETRA_URL", "https://127.0.0.1:30870"), "/")
	hc := &http.Client{Timeout: 20 * time.Second}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_TLS_INSECURE")), "true") {
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}} // explicit local/self-signed opt-in
	}
	return &client{
		base:       base,
		apiKey:     os.Getenv("NETRA_API_KEY"),
		actor:      env("NETRA_MCP_ACTOR", "mcp:hermes"),
		httpClient: hc,
	}
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// do performs one HTTP call against the controller. A non-nil error
// means the request never got a response (DNS/connect/TLS/timeout); a
// non-2xx status is returned as a normal (body, status, nil) result for
// the caller to translate into an MCP isError result, since it's a
// meaningful answer from the controller, not a transport failure.
func (c *client) do(ctx context.Context, method, path string, body []byte, extra map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	req.Header.Set("X-Netra-Actor", c.actor)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return out, resp.StatusCode, nil
}
