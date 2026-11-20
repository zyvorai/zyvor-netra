// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// rfc3339Micro matches metav1.MicroTime's own wire format (exactly six
// fractional-second digits). time.RFC3339Nano is the wrong layout to write
// with: its ".999999999" trims trailing zeros, so it frequently emits eight
// or nine fractional digits instead of six — a real Kubernetes API server
// rejects that with "cannot be handled as a Lease: parsing time ... as
// ...Z07:00", since it decodes acquireTime/renewTime as MicroTime, not
// arbitrary-precision RFC3339. This only ever showed up against a live
// server; the fake HTTP backend the unit tests use doesn't validate the
// JSON payload's time format, so it was invisible until now.
const rfc3339Micro = "2006-01-02T15:04:05.000000Z07:00"

type leaseDocument struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace,omitempty"`
		ResourceVersion string `json:"resourceVersion,omitempty"`
	} `json:"metadata"`
	Spec struct {
		HolderIdentity       string `json:"holderIdentity,omitempty"`
		LeaseDurationSeconds int32  `json:"leaseDurationSeconds,omitempty"`
		AcquireTime          string `json:"acquireTime,omitempty"`
		RenewTime            string `json:"renewTime,omitempty"`
		LeaseTransitions     int32  `json:"leaseTransitions,omitempty"`
	} `json:"spec"`
}

// TryAcquireOrRenewLease implements the small subset of coordination.k8s.io/v1
// Lease semantics Netra needs for active/passive controller election. Conflict
// responses are treated as a lost race rather than as an API failure.
func (c *Client) TryAcquireOrRenewLease(ctx context.Context, namespace, name, identity string, duration time.Duration) (bool, error) {
	if strings.TrimSpace(namespace) == "" || strings.TrimSpace(name) == "" || strings.TrimSpace(identity) == "" {
		return false, fmt.Errorf("lease namespace, name and identity are required")
	}
	seconds := int32(math.Ceil(duration.Seconds()))
	if seconds < 5 {
		seconds = 5
	}
	now := time.Now().UTC()
	lease, found, err := c.getLease(ctx, namespace, name)
	if err != nil {
		return false, err
	}
	if !found {
		var doc leaseDocument
		doc.APIVersion = "coordination.k8s.io/v1"
		doc.Kind = "Lease"
		doc.Metadata.Name = name
		doc.Metadata.Namespace = namespace
		doc.Spec.HolderIdentity = identity
		doc.Spec.LeaseDurationSeconds = seconds
		doc.Spec.AcquireTime = now.Format(rfc3339Micro)
		doc.Spec.RenewTime = now.Format(rfc3339Micro)
		status, err := c.writeLease(ctx, http.MethodPost, "/apis/coordination.k8s.io/v1/namespaces/"+url.PathEscape(namespace)+"/leases", doc)
		if err != nil {
			return false, err
		}
		if status == http.StatusConflict {
			return false, nil
		}
		return status >= 200 && status < 300, nil
	}

	holder := lease.Spec.HolderIdentity
	expired := holder == "" || leaseExpired(lease, now)
	if holder != identity && !expired {
		return false, nil
	}
	if holder != identity {
		lease.Spec.LeaseTransitions++
		lease.Spec.AcquireTime = now.Format(rfc3339Micro)
	}
	lease.APIVersion = "coordination.k8s.io/v1"
	lease.Kind = "Lease"
	lease.Spec.HolderIdentity = identity
	lease.Spec.LeaseDurationSeconds = seconds
	lease.Spec.RenewTime = now.Format(rfc3339Micro)
	status, err := c.writeLease(ctx, http.MethodPut, "/apis/coordination.k8s.io/v1/namespaces/"+url.PathEscape(namespace)+"/leases/"+url.PathEscape(name), lease)
	if err != nil {
		return false, err
	}
	if status == http.StatusConflict {
		return false, nil
	}
	return status >= 200 && status < 300, nil
}

func (c *Client) ReleaseLease(ctx context.Context, namespace, name, identity string) error {
	lease, found, err := c.getLease(ctx, namespace, name)
	if err != nil || !found {
		return err
	}
	if lease.Spec.HolderIdentity != identity {
		return nil
	}
	lease.Spec.HolderIdentity = ""
	lease.Spec.RenewTime = time.Now().UTC().Format(rfc3339Micro)
	status, err := c.writeLease(ctx, http.MethodPut, "/apis/coordination.k8s.io/v1/namespaces/"+url.PathEscape(namespace)+"/leases/"+url.PathEscape(name), lease)
	if err != nil {
		return err
	}
	if status == http.StatusConflict || status == http.StatusNotFound {
		return nil
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("release lease returned HTTP %d", status)
	}
	return nil
}

func (c *Client) getLease(ctx context.Context, namespace, name string) (leaseDocument, bool, error) {
	var out leaseDocument
	p := "/apis/coordination.k8s.io/v1/namespaces/" + url.PathEscape(namespace) + "/leases/" + url.PathEscape(name)
	status, body, err := c.leaseRequest(ctx, http.MethodGet, p, nil)
	if err != nil {
		return out, false, err
	}
	if status == http.StatusNotFound {
		return out, false, nil
	}
	if status < 200 || status >= 300 {
		return out, false, fmt.Errorf("kubernetes Lease API HTTP %d: %s", status, string(body))
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, false, fmt.Errorf("decode Lease: %w", err)
	}
	return out, true, nil
}

func (c *Client) writeLease(ctx context.Context, method, p string, lease leaseDocument) (int, error) {
	body, err := json.Marshal(lease)
	if err != nil {
		return 0, err
	}
	status, response, err := c.leaseRequest(ctx, method, p, body)
	if err != nil {
		return 0, err
	}
	if status == http.StatusConflict || status == http.StatusNotFound {
		return status, nil
	}
	if status < 200 || status >= 300 {
		return status, fmt.Errorf("kubernetes Lease API HTTP %d: %s", status, string(response))
	}
	return status, nil
}

func (c *Client) leaseRequest(ctx context.Context, method, p string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+p, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, nil
}

func leaseExpired(lease leaseDocument, now time.Time) bool {
	stamp := lease.Spec.RenewTime
	if stamp == "" {
		stamp = lease.Spec.AcquireTime
	}
	t, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		return true
	}
	d := time.Duration(lease.Spec.LeaseDurationSeconds) * time.Second
	if d <= 0 {
		return true
	}
	return !now.Before(t.Add(d))
}
