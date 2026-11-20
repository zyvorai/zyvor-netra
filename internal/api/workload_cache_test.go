// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestWorkloadInventoryCacheGetMissingNode(t *testing.T) {
	c := newWorkloadInventoryCache()
	if _, ok := c.get("node-1"); ok {
		t.Fatal("expected ok=false for a node that has never had a successful fetch")
	}
}

func TestWorkloadInventoryCacheSetThenGet(t *testing.T) {
	c := newWorkloadInventoryCache()
	items := []models.WorkloadIdentity{{UID: "u1", Namespace: "prod", Pod: "api-1"}}
	c.set("node-1", items)
	got, ok := c.get("node-1")
	if !ok || len(got) != 1 || got[0].Pod != "api-1" {
		t.Fatalf("get() = %+v, %v, want the set items", got, ok)
	}
}

func TestWorkloadInventoryCacheIsPerNode(t *testing.T) {
	c := newWorkloadInventoryCache()
	c.set("node-1", []models.WorkloadIdentity{{Pod: "a"}})
	if _, ok := c.get("node-2"); ok {
		t.Fatal("expected node-2 to have no cached entry")
	}
}

func TestWorkloadInventoryCacheOverwritesOnNewSet(t *testing.T) {
	c := newWorkloadInventoryCache()
	c.set("node-1", []models.WorkloadIdentity{{Pod: "old"}})
	c.set("node-1", []models.WorkloadIdentity{{Pod: "new"}})
	got, _ := c.get("node-1")
	if len(got) != 1 || got[0].Pod != "new" {
		t.Fatalf("get() = %+v, want the latest set", got)
	}
}
