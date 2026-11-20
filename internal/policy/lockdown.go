// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

var dnsLabel = regexp.MustCompile(`[^a-z0-9-]+`)

func LockdownPolicyName(workload string) string {
	s := strings.ToLower(strings.TrimSpace(workload))
	s = dnsLabel.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "workload"
	}
	name := "netra-lockdown-" + s
	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "-")
	}
	return name
}
func IsLockdownPolicy(name string) bool { return strings.HasPrefix(name, "netra-lockdown-") }
func RecommendedSelector(labels map[string]string, kind, name string) map[string]string {
	if labels == nil {
		labels = map[string]string{}
	}
	out := map[string]string{}
	if v := labels["app.kubernetes.io/name"]; v != "" {
		out["app.kubernetes.io/name"] = v
		if inst := labels["app.kubernetes.io/instance"]; inst != "" {
			out["app.kubernetes.io/instance"] = inst
		}
		return out
	}
	if v := labels["app"]; v != "" {
		return map[string]string{"app": v}
	}
	if kind == "vm" {
		if v := labels["kubevirt.io/domain"]; v != "" {
			return map[string]string{"kubevirt.io/domain": v}
		}
		if v := labels["vm.kubevirt.io/name"]; v != "" {
			return map[string]string{"vm.kubevirt.io/name": v}
		}
	}
	skip := map[string]bool{"pod-template-hash": true, "controller-revision-hash": true, "statefulset.kubernetes.io/pod-name": true, "apps.kubernetes.io/pod-index": true, "batch.kubernetes.io/job-name": true, "batch.kubernetes.io/controller-uid": true, "job-name": true, "controller-uid": true, "kubectl.kubernetes.io/restartedAt": true}
	for k, v := range labels {
		if skip[k] || strings.HasPrefix(k, "k8s.v1.cni.cncf.io") {
			continue
		}
		out[k] = v
	}
	if len(out) > 0 {
		return out
	}
	if name != "" {
		return map[string]string{"io.kubernetes.pod.name": name}
	}
	return map[string]string{}
}
func Lockdown(r models.LockdownRequest) ([]byte, error) {
	if strings.TrimSpace(r.Name) == "" {
		return nil, fmt.Errorf("name is required")
	}
	if r.Namespace == "" {
		r.Namespace = "default"
	}
	if len(r.Selector) == 0 {
		return nil, fmt.Errorf("selector cannot be empty")
	}
	dns := map[string]any{"toEndpoints": []any{map[string]any{"matchLabels": map[string]string{"k8s:io.kubernetes.pod.namespace": "kube-system", "k8s:k8s-app": "kube-dns"}}}, "toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": "53", "protocol": "UDP"}, map[string]any{"port": "53", "protocol": "TCP"}}}}}
	obj := map[string]any{"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy", "metadata": map[string]any{"name": LockdownPolicyName(r.Name), "namespace": r.Namespace, "labels": map[string]string{"app.kubernetes.io/managed-by": "netra", "netra.zyvor.dev/lockdown": "true", "netra.zyvor.dev/workload": sanitizeLabelValue(r.Name)}}, "spec": map[string]any{"endpointSelector": map[string]any{"matchLabels": r.Selector}, "ingress": []any{}, "egress": []any{dns}}}
	return json.MarshalIndent(obj, "", "  ")
}
func sanitizeLabelValue(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = dnsLabel.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	if s == "" {
		return "workload"
	}
	return s
}
func PolicyMatchesLabels(policyJSON []byte, labels map[string]string) bool {
	var d struct {
		Spec struct {
			EndpointSelector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"endpointSelector"`
		} `json:"spec"`
	}
	if json.Unmarshal(policyJSON, &d) != nil || len(d.Spec.EndpointSelector.MatchLabels) == 0 {
		return false
	}
	if labels == nil {
		labels = map[string]string{}
	}
	for k, v := range d.Spec.EndpointSelector.MatchLabels {
		key := strings.TrimPrefix(k, "k8s:")
		got, ok := labels[key]
		if !ok {
			got, ok = labels[k]
		}
		if !ok || got != v {
			return false
		}
	}
	return true
}
func SummarizeMatchingPolicies(listJSON []byte, namespace string, labels map[string]string) []models.PolicyRef {
	var l struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(listJSON, &l) != nil {
		return nil
	}
	out := []models.PolicyRef{}
	for _, raw := range l.Items {
		var m struct {
			Metadata struct{ Name, Namespace string } `json:"metadata"`
		}
		if json.Unmarshal(raw, &m) != nil || !PolicyMatchesLabels(raw, labels) {
			continue
		}
		ns := m.Metadata.Namespace
		if ns == "" {
			ns = namespace
		}
		out = append(out, models.PolicyRef{Name: m.Metadata.Name, Namespace: ns, Lockdown: IsLockdownPolicy(m.Metadata.Name)})
	}
	return out
}
