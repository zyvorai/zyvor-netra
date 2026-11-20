// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package policy

import (
	"encoding/json"
	"fmt"
	"github.com/zyvorai/netra/internal/models"
	"net/netip"
	"strings"
)

func Build(r models.BuildPolicyRequest) ([]byte, error) {
	if strings.TrimSpace(r.Name) == "" {
		return nil, fmt.Errorf("name is required")
	}
	if r.Namespace == "" {
		r.Namespace = "default"
	}
	if len(r.Selector) == 0 {
		return nil, fmt.Errorf("selector cannot be empty; Netra refuses namespace-wide selection in the guided builder")
	}
	if len(r.To) == 0 {
		return nil, fmt.Errorf("at least one destination is required")
	}
	proto := strings.ToUpper(strings.TrimSpace(r.Protocol))
	if proto == "" {
		proto = "TCP"
	}
	if proto != "TCP" && proto != "UDP" && proto != "ANY" {
		return nil, fmt.Errorf("protocol must be TCP, UDP, or ANY")
	}
	rule := map[string]any{}
	switch strings.ToLower(strings.TrimSpace(r.Kind)) {
	case "fqdn":
		arr := []map[string]string{}
		for _, d := range r.To {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if strings.Contains(d, "*") {
				arr = append(arr, map[string]string{"matchPattern": d})
			} else {
				arr = append(arr, map[string]string{"matchName": d})
			}
		}
		if len(arr) == 0 {
			return nil, fmt.Errorf("no valid FQDN destination")
		}
		rule["toFQDNs"] = arr
	case "cidr":
		arr := []string{}
		for _, d := range r.To {
			if p, err := netip.ParsePrefix(strings.TrimSpace(d)); err == nil {
				arr = append(arr, p.String())
			} else if a, err := netip.ParseAddr(strings.TrimSpace(d)); err == nil {
				bits := 32
				if a.Is6() {
					bits = 128
				}
				arr = append(arr, netip.PrefixFrom(a, bits).String())
			} else {
				return nil, fmt.Errorf("invalid CIDR/IP %q", d)
			}
		}
		rule["toCIDR"] = arr
	case "entity":
		rule["toEntities"] = r.To
	default:
		return nil, fmt.Errorf("kind must be fqdn, cidr, or entity")
	}
	if r.Port > 0 {
		p := map[string]any{"port": fmt.Sprint(r.Port)}
		if proto != "ANY" {
			p["protocol"] = proto
		}
		rule["toPorts"] = []any{map[string]any{"ports": []any{p}}}
	}
	egress := []any{rule}
	if r.IncludeDNS {
		egress = append(egress, map[string]any{"toEndpoints": []any{map[string]any{"matchLabels": map[string]string{"k8s:io.kubernetes.pod.namespace": "kube-system", "k8s:k8s-app": "kube-dns"}}}, "toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": "53", "protocol": "UDP"}, map[string]any{"port": "53", "protocol": "TCP"}}}}})
	}
	obj := map[string]any{"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy", "metadata": map[string]any{"name": r.Name, "namespace": r.Namespace, "labels": map[string]string{"app.kubernetes.io/managed-by": "netra"}}, "spec": map[string]any{"endpointSelector": map[string]any{"matchLabels": r.Selector}, "egress": egress}}
	return json.MarshalIndent(obj, "", "  ")
}
