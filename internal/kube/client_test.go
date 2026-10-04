package kube

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtractIdentity(t *testing.T) {
	ns, n, err := ExtractIdentity([]byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"eg"}}`))
	if err != nil || ns != "default" || n != "eg" {
		t.Fatalf("%s %s %v", ns, n, err)
	}
}

func TestPreparePolicyForApplyRemovesServerFields(t *testing.T) {
	in := []byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"eg","namespace":"ns","resourceVersion":"12","uid":"u","labels":{"team":"net"}},"spec":{"endpointSelector":{"matchLabels":{"app":"a"}}},"status":{"nodes":[]}}`)
	out, err := PreparePolicyForApply(in)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	meta := doc["metadata"].(map[string]any)
	if _, ok := meta["resourceVersion"]; ok {
		t.Fatal("resourceVersion was not removed")
	}
	if _, ok := doc["status"]; ok {
		t.Fatal("status was not removed")
	}
	if meta["labels"].(map[string]any)["team"] != "net" {
		t.Fatal("labels should be preserved")
	}
}

func TestListWorkloads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/pods") {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if got := r.URL.Query().Get("fieldSelector"); got != "spec.nodeName=node-a,"+activePodsSelector {
			t.Fatalf("selector=%q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"uid":"u1","name":"api-1","namespace":"payments","labels":{"app":"api"},"ownerReferences":[{"kind":"ReplicaSet","name":"api-7d9","controller":true}]},"spec":{"nodeName":"node-a"}}]}`))
	}))
	defer srv.Close()
	c := &Client{base: srv.URL, http: srv.Client()}
	items, err := c.ListWorkloads(context.Background(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Namespace != "payments" || items[0].WorkloadKind != "ReplicaSet" || items[0].Labels["app"] != "api" {
		t.Fatalf("items=%#v", items)
	}
}
