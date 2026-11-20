// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type Client struct {
	base, token string
	http        *http.Client
	streamHTTP  *http.Client
	tlsConfig   *tls.Config
}

func NewFromEnvironment() (*Client, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if host == "" {
		host = "kubernetes.default.svc"
	}
	if port == "" {
		port = "443"
	}
	base := "https://" + host + ":" + port
	tokenBytes, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	ca, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if len(ca) > 0 {
		pool.AppendCertsFromPEM(ca)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	tr := &http.Transport{TLSClientConfig: tlsCfg}
	return &Client{
		base:       base,
		token:      strings.TrimSpace(string(tokenBytes)),
		http:       &http.Client{Timeout: 15 * time.Second, Transport: tr},
		streamHTTP: &http.Client{Timeout: 0, Transport: tr},
		tlsConfig:  tlsCfg,
	}, nil
}

// NewForTesting builds a Client pointing at a fake backend (typically an
// httptest.Server) instead of a real in-cluster Kubernetes API server —
// NewFromEnvironment always dials HTTPS with in-cluster credentials, which
// a plain httptest server can't satisfy. Exported so other packages' tests
// (internal/gitops's Reconcile/Resync tests, in particular) can exercise
// GetPolicy/ApplyPolicy/etc. against a fake HTTP backend. Not meant for
// production use — there is no token/TLS here at all.
func NewForTesting(base string, httpClient *http.Client) *Client {
	return &Client{base: base, http: httpClient, streamHTTP: httpClient}
}

func (c *Client) do(ctx context.Context, method, p string, body []byte, contentType string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+p, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kubernetes API %s: %s", resp.Status, string(b))
	}
	return b, nil
}
func esc(s string) string { return url.PathEscape(s) }
func (c *Client) ListPolicies(ctx context.Context, ns string) ([]byte, error) {
	return c.do(ctx, "GET", "/apis/cilium.io/v2/namespaces/"+esc(ns)+"/ciliumnetworkpolicies", nil, "")
}

func (c *Client) GetPolicy(ctx context.Context, ns, name string) ([]byte, bool, error) {
	p := "/apis/cilium.io/v2/namespaces/" + esc(ns) + "/ciliumnetworkpolicies/" + esc(name)
	req, err := http.NewRequestWithContext(ctx, "GET", c.base+p, nil)
	if err != nil {
		return nil, false, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode >= 300 {
		return nil, false, fmt.Errorf("kubernetes API %s: %s", resp.Status, string(b))
	}
	return b, true, nil
}

func (c *Client) ApplyPolicy(ctx context.Context, ns, name string, body []byte, dry bool) ([]byte, error) {
	q := "?fieldManager=netra&force=true"
	if dry {
		q += "&dryRun=All"
	}
	return c.do(ctx, "PATCH", "/apis/cilium.io/v2/namespaces/"+esc(ns)+"/ciliumnetworkpolicies/"+esc(name)+q, body, "application/apply-patch+yaml")
}
func (c *Client) DeletePolicy(ctx context.Context, ns, name string) error {
	_, err := c.do(ctx, "DELETE", "/apis/cilium.io/v2/namespaces/"+esc(ns)+"/ciliumnetworkpolicies/"+esc(name), []byte(`{"propagationPolicy":"Background"}`), "application/json")
	return err
}

func (c *Client) ListWorkloads(ctx context.Context, node string) ([]models.WorkloadIdentity, error) {
	sel := activePodsSelector
	if strings.TrimSpace(node) != "" {
		sel = "spec.nodeName=" + strings.TrimSpace(node) + "," + sel
	}
	p := "/api/v1/pods?" + url.Values{"fieldSelector": {sel}}.Encode()
	type podItem struct {
		Metadata struct {
			UID       string            `json:"uid"`
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Labels    map[string]string `json:"labels"`
			Owners    []struct {
				Kind       string `json:"kind"`
				Name       string `json:"name"`
				Controller bool   `json:"controller"`
			} `json:"ownerReferences"`
		} `json:"metadata"`
		Spec struct {
			NodeName           string `json:"nodeName"`
			ServiceAccountName string `json:"serviceAccountName"`
		} `json:"spec"`
	}
	items, err := listItems[podItem](ctx, c, p)
	if err != nil {
		return nil, fmt.Errorf("list pod inventory: %w", err)
	}
	out := make([]models.WorkloadIdentity, 0, len(items))
	for _, pod := range items {
		w := models.WorkloadIdentity{
			UID: pod.Metadata.UID, Namespace: pod.Metadata.Namespace, Pod: pod.Metadata.Name,
			Node: pod.Spec.NodeName, Labels: pod.Metadata.Labels,
			ServiceAccountName: pod.Spec.ServiceAccountName,
		}
		for _, owner := range pod.Metadata.Owners {
			if owner.Controller || w.WorkloadKind == "" {
				w.WorkloadKind, w.WorkloadName = owner.Kind, owner.Name
			}
			if owner.Controller {
				break
			}
		}
		out = append(out, w)
	}
	return out, nil
}

func ExtractIdentity(b []byte) (string, string, error) {
	var x struct {
		Kind     string                           `json:"kind"`
		Metadata struct{ Name, Namespace string } `json:"metadata"`
	}
	if err := json.Unmarshal(b, &x); err != nil {
		return "", "", fmt.Errorf("policy must be JSON: %w", err)
	}
	if x.Kind != "CiliumNetworkPolicy" {
		return "", "", fmt.Errorf("kind must be CiliumNetworkPolicy")
	}
	if strings.TrimSpace(x.Metadata.Name) == "" {
		return "", "", fmt.Errorf("metadata.name is required")
	}
	ns := strings.TrimSpace(x.Metadata.Namespace)
	if ns == "" {
		ns = "default"
	}
	if path.Clean(ns) != ns || strings.Contains(ns, "/") {
		return "", "", fmt.Errorf("invalid namespace")
	}
	return ns, x.Metadata.Name, nil
}

// PreparePolicyForApply removes API-server-owned fields from a live CNP so the
// result can safely be stored as a rollback snapshot and later server-side applied.
// Policy fields, labels, annotations and unknown Cilium rule fields are preserved.
func PreparePolicyForApply(b []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("policy must be JSON: %w", err)
	}
	delete(doc, "status")
	if meta, ok := doc["metadata"].(map[string]any); ok {
		for _, key := range []string{"creationTimestamp", "deletionGracePeriodSeconds", "deletionTimestamp", "generation", "managedFields", "resourceVersion", "selfLink", "uid"} {
			delete(meta, key)
		}
	}
	return json.Marshal(doc)
}
