package workload

import (
	"github.com/zyvorai/netra/internal/cgroupmeta"
	"github.com/zyvorai/netra/internal/models"
	"testing"
)

func TestResolveNamespaceAndLabels(t *testing.T) {
	cgs := map[uint64]cgroupmeta.Identity{42: {CgroupID: 42, PodUID: "u1", ContainerID: "c1", Path: "/cg/pod"}}
	pods := []models.WorkloadIdentity{{UID: "u1", Namespace: "payments", Pod: "api-1", WorkloadKind: "ReplicaSet", WorkloadName: "api-7d9", Labels: map[string]string{"app": "api"}}}
	resolved, selected := Resolve(cgs, pods, []models.EBPFWorkloadScope{{Namespace: "payments", Labels: map[string]string{"app": "api"}}})
	if resolved[42].Pod != "api-1" || resolved[42].ContainerID != "c1" {
		t.Fatalf("resolved=%#v", resolved[42])
	}
	if _, ok := selected[42]; !ok {
		t.Fatal("expected cgroup 42 selected")
	}
}

func TestMatchRejectsEmptyScope(t *testing.T) {
	if Match(models.EBPFWorkloadScope{}, models.WorkloadIdentity{Namespace: "default"}) {
		t.Fatal("empty scope must never match")
	}
}
