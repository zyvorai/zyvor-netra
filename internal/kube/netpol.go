// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// ListNetworkPolicyItems lists every networking.k8s.io/v1 NetworkPolicy, or
// those of one namespace. Read-only: Netra never writes this resource.
func (c *Client) ListNetworkPolicyItems(ctx context.Context, ns string) ([]json.RawMessage, error) {
	p := "/apis/networking.k8s.io/v1/networkpolicies"
	if ns != "" {
		p = "/apis/networking.k8s.io/v1/namespaces/" + esc(ns) + "/networkpolicies"
	}
	items, err := listItems[json.RawMessage](ctx, c, p)
	if err != nil {
		return nil, fmt.Errorf("list network policies: %w", err)
	}
	return items, nil
}

// ListActivePodItems lists the pods that are not finished, cluster wide or in
// one namespace.
func (c *Client) ListActivePodItems(ctx context.Context, ns string) ([]json.RawMessage, error) {
	p := "/api/v1/pods"
	if ns != "" {
		p = "/api/v1/namespaces/" + esc(ns) + "/pods"
	}
	p += "?" + url.Values{"fieldSelector": {activePodsSelector}}.Encode()
	items, err := listItems[json.RawMessage](ctx, c, p)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	return items, nil
}
