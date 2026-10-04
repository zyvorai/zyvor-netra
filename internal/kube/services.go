// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package kube

import (
	"context"
	"fmt"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

func (c *Client) ListServices(ctx context.Context, ns string) ([]models.ServiceInfo, error) {
	p := "/api/v1/services"
	if strings.TrimSpace(ns) != "" {
		p = "/api/v1/namespaces/" + esc(ns) + "/services"
	}
	type serviceItem struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			ClusterIP string            `json:"clusterIP"`
			Selector  map[string]string `json:"selector"`
			Ports     []struct {
				Name     string `json:"name"`
				Port     uint16 `json:"port"`
				Protocol string `json:"protocol"`
			} `json:"ports"`
		} `json:"spec"`
	}
	items, err := listItems[serviceItem](ctx, c, p)
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	out := make([]models.ServiceInfo, 0, len(items))
	for _, it := range items {
		if it.Spec.ClusterIP == "" || strings.EqualFold(it.Spec.ClusterIP, "None") {
			continue
		}
		svc := models.ServiceInfo{Name: it.Metadata.Name, Namespace: it.Metadata.Namespace, ClusterIP: it.Spec.ClusterIP, Selector: it.Spec.Selector}
		for _, p := range it.Spec.Ports {
			svc.Ports = append(svc.Ports, models.ServicePortInfo{Name: p.Name, Port: p.Port, Protocol: p.Protocol})
		}
		out = append(out, svc)
	}
	return out, nil
}
