// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package workload

import (
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/cgroupmeta"
	"github.com/zyvorai/netra/internal/models"
)

// Resolve joins cgroup-v2 identities with Kubernetes pod metadata and returns
// both an attribution table and the cgroup IDs selected for enforcement.
func Resolve(cgroups map[uint64]cgroupmeta.Identity, pods []models.WorkloadIdentity, scopes []models.EBPFWorkloadScope) (map[uint64]models.WorkloadIdentity, map[uint64]struct{}) {
	byUID := make(map[string]models.WorkloadIdentity, len(pods))
	for _, p := range pods {
		byUID[strings.ToLower(p.UID)] = p
	}
	resolved := make(map[uint64]models.WorkloadIdentity, len(cgroups))
	selected := map[uint64]struct{}{}
	for id, cg := range cgroups {
		w, ok := byUID[strings.ToLower(cg.PodUID)]
		if ok {
			w.CgroupID, w.ContainerID, w.CgroupPath = id, cg.ContainerID, cg.Path
		} else {
			w = models.WorkloadIdentity{UID: cg.PodUID, CgroupID: id, ContainerID: cg.ContainerID, CgroupPath: cg.Path}
		}
		resolved[id] = w
		for _, scope := range scopes {
			if Match(scope, w) {
				selected[id] = struct{}{}
				break
			}
		}
	}
	// Exact cgroup scopes are also useful for non-Kubernetes systemd units.
	for _, scope := range scopes {
		if scope.CgroupID != 0 {
			selected[scope.CgroupID] = struct{}{}
		}
	}
	return resolved, selected
}

func Match(scope models.EBPFWorkloadScope, w models.WorkloadIdentity) bool {
	if scope.CgroupID != 0 && scope.CgroupID != w.CgroupID {
		return false
	}
	if scope.Namespace != "" && scope.Namespace != w.Namespace {
		return false
	}
	if scope.Pod != "" && scope.Pod != w.Pod {
		return false
	}
	if scope.WorkloadKind != "" && !strings.EqualFold(scope.WorkloadKind, w.WorkloadKind) {
		return false
	}
	if scope.WorkloadName != "" && scope.WorkloadName != w.WorkloadName {
		return false
	}
	for k, v := range scope.Labels {
		if w.Labels == nil || w.Labels[k] != v {
			return false
		}
	}
	return scope.CgroupID != 0 || scope.Namespace != "" || scope.Pod != "" || scope.WorkloadKind != "" || scope.WorkloadName != "" || len(scope.Labels) > 0
}

func Sorted(in map[uint64]models.WorkloadIdentity) []models.WorkloadIdentity {
	out := make([]models.WorkloadIdentity, 0, len(in))
	for _, w := range in {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		if out[i].Pod != out[j].Pod {
			return out[i].Pod < out[j].Pod
		}
		return out[i].CgroupID < out[j].CgroupID
	})
	return out
}
