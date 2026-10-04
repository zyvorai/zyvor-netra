// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/policy"
)

func (s *Server) listPods(w http.ResponseWriter, r *http.Request) {
	ns := strings.TrimSpace(r.URL.Query().Get("namespace"))
	items, err := s.kube.ListAllPods(r.Context(), ns)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	type row struct {
		models.PodInfo
		LockedDown bool `json:"lockedDown"`
	}
	lockNames := map[string]bool{}
	seen := map[string]bool{}
	for _, it := range items {
		if seen[it.Namespace] {
			continue
		}
		seen[it.Namespace] = true
		pols, err := s.kube.ListPolicies(r.Context(), it.Namespace)
		if err != nil {
			continue
		}
		var p struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if json.Unmarshal(pols, &p) != nil {
			continue
		}
		for _, x := range p.Items {
			if policy.IsLockdownPolicy(x.Metadata.Name) {
				lockNames[it.Namespace+"/"+x.Metadata.Name] = true
			}
		}
	}
	out := make([]row, 0, len(items))
	for _, it := range items {
		out = append(out, row{PodInfo: it, LockedDown: lockNames[it.Namespace+"/"+policy.LockdownPolicyName(it.Name)]})
	}
	writeJSON(w, 200, map[string]any{"items": out})
}
func (s *Server) listVMs(w http.ResponseWriter, r *http.Request) {
	ns := strings.TrimSpace(r.URL.Query().Get("namespace"))
	items, available, err := s.kube.ListVMs(r.Context(), ns)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	type row struct {
		models.VMInfo
		LockedDown bool `json:"lockedDown"`
	}
	out := make([]row, 0, len(items))
	for _, it := range items {
		_, found, _ := s.kube.GetPolicy(r.Context(), it.Namespace, policy.LockdownPolicyName(it.Name))
		out = append(out, row{VMInfo: it, LockedDown: found})
	}
	writeJSON(w, 200, map[string]any{"available": available, "items": out})
}
func (s *Server) workloadDetail(w http.ResponseWriter, r *http.Request) {
	kind := strings.ToLower(r.PathValue("kind"))
	ns, name := r.PathValue("namespace"), r.PathValue("name")
	if ns == "" || name == "" {
		errorJSON(w, 400, "namespace and name are required")
		return
	}
	d := models.WorkloadDetail{Kind: kind, Name: name, Namespace: ns}
	switch kind {
	case "pod":
		p, err := s.kube.GetPod(r.Context(), ns, name)
		if err != nil {
			errorJSON(w, 502, err.Error())
			return
		}
		d.Phase = p.Phase
		d.Node = p.Node
		d.PodIP = p.PodIP
		d.PodName = p.Name
		d.Ready = p.Ready
		d.Labels = p.Labels
		d.OwnerKind = p.OwnerKind
		d.OwnerName = p.OwnerName
		d.Containers = p.Containers
		if len(p.Containers) > 0 {
			d.DefaultContainer = p.Containers[0].Name
		}
	case "vm":
		vm, available, err := s.kube.GetVMI(r.Context(), ns, name)
		if err != nil {
			errorJSON(w, 502, err.Error())
			return
		}
		if !available {
			errorJSON(w, 404, "KubeVirt is not available in this cluster")
			return
		}
		if vm == nil {
			errorJSON(w, 404, "vm not found")
			return
		}
		d.Phase = vm.Phase
		d.Node = vm.Node
		d.PodIP = vm.PodIP
		d.PodName = vm.PodName
		d.Running = vm.Running
		d.Labels = vm.Labels
	default:
		errorJSON(w, 400, "kind must be pod or vm")
		return
	}
	d.RecommendedSelector = policy.RecommendedSelector(d.Labels, kind, name)
	d.LockdownPolicy = policy.LockdownPolicyName(name)
	list, err := s.kube.ListPolicies(r.Context(), ns)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	d.Policies = policy.SummarizeMatchingPolicies(list, ns, d.Labels)
	_, d.LockedDown, _ = s.kube.GetPolicy(r.Context(), ns, d.LockdownPolicy)
	for _, p := range d.Policies {
		if p.Lockdown || p.Name == d.LockdownPolicy {
			d.LockedDown = true
		}
	}
	writeJSON(w, 200, d)
}
func (s *Server) lockdownPolicy(w http.ResponseWriter, r *http.Request) {
	var req models.LockdownRequest
	if err := decodeJSON(r, &req, 1<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if req.Namespace == "" {
		req.Namespace = "default"
	}
	switch strings.ToLower(req.Kind) {
	case "pod":
		if p, err := s.kube.GetPod(r.Context(), req.Namespace, req.Name); err == nil && p != nil && len(req.Selector) == 0 {
			req.Selector = policy.RecommendedSelector(p.Labels, "pod", req.Name)
		}
	case "vm":
		if vm, ok, err := s.kube.GetVMI(r.Context(), req.Namespace, req.Name); err == nil && ok && vm != nil && len(req.Selector) == 0 {
			req.Selector = policy.RecommendedSelector(vm.Labels, "vm", req.Name)
		}
	default:
		if req.Kind == "" {
			req.Kind = "pod"
		}
	}
	if len(req.Selector) == 0 {
		req.Selector = policy.RecommendedSelector(nil, req.Kind, req.Name)
	}
	b, err := policy.Lockdown(req)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	writeRawJSON(w, 200, b)
}
func (s *Server) unlockPolicy(w http.ResponseWriter, r *http.Request) {
	ns, name := r.PathValue("namespace"), r.PathValue("name")
	r.SetPathValue("name", policy.LockdownPolicyName(name))
	r.SetPathValue("namespace", ns)
	s.deletePolicy(w, r)
}
