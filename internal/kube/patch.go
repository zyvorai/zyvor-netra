// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// PatchContainerEnv strategic-merge-patches a Deployment or DaemonSet
// container env var. kind is "deployments" or "daemonsets".
func (c *Client) PatchContainerEnv(ctx context.Context, kind, namespace, name, container, envKey, envValue string) error {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind != "deployments" && kind != "daemonsets" {
		return fmt.Errorf("kind must be deployments or daemonsets")
	}
	if namespace == "" || name == "" || container == "" || envKey == "" {
		return fmt.Errorf("namespace, name, container, and envKey are required")
	}
	patch := map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []map[string]any{{
						"name": container,
						"env": []map[string]string{{
							"name":  envKey,
							"value": envValue,
						}},
					}},
				},
			},
		},
	}
	body, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/%s/%s?fieldManager=netra", esc(namespace), kind, esc(name))
	return c.patch(ctx, path, body, "application/strategic-merge-patch+json")
}

func (c *Client) patch(ctx context.Context, p string, body []byte, contentType string) error {
	_, err := c.do(ctx, "PATCH", p, body, contentType)
	return err
}

// ControllerNamespace returns the in-cluster namespace for Netra workloads.
func ControllerNamespace() string {
	if ns := strings.TrimSpace(os.Getenv("NETRA_NAMESPACE")); ns != "" {
		return ns
	}
	b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err == nil {
		if ns := strings.TrimSpace(string(b)); ns != "" {
			return ns
		}
	}
	return "netra-system"
}
