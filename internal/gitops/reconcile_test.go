// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package gitops

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/store"
)

// fakeKube is a minimal in-memory Cilium-policy backend: enough of
// GET/PATCH .../ciliumnetworkpolicies/{name} for internal/kube.Client's
// GetPolicy/ApplyPolicy to work against via kube.NewForTesting.
type fakeKube struct {
	mu       sync.Mutex
	policies map[string][]byte // "ns/name" -> last-applied (non-dry-run) body
}

func newFakeKube(t *testing.T) (*kube.Client, *fakeKube) {
	t.Helper()
	fk := &fakeKube{policies: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/apis/cilium.io/v2/namespaces/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		parts := strings.Split(rest, "/")
		if len(parts) != 3 || parts[1] != "ciliumnetworkpolicies" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		key := parts[0] + "/" + parts[2]
		switch r.Method {
		case http.MethodGet:
			fk.mu.Lock()
			b, ok := fk.policies[key]
			fk.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		case http.MethodPatch:
			body, _ := io.ReadAll(r.Body)
			dry := r.URL.Query().Get("dryRun") == "All"
			if !dry {
				fk.mu.Lock()
				fk.policies[key] = body
				fk.mu.Unlock()
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(body)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(srv.Close)
	return kube.NewForTesting(srv.URL, srv.Client()), fk
}

func manifestJSON(t *testing.T, ns, name string, egress string) []byte {
	t.Helper()
	return []byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"` + name + `","namespace":"` + ns + `"},"spec":{"endpointSelector":{"matchLabels":{"app":"` + name + `"}},"egress":[` + egress + `]}}`)
}

func TestReconcileAppliesLowRiskWhenAutoApply(t *testing.T) {
	k, _ := newFakeKube(t)
	st := store.New()
	m := Manifest{Path: "a.yaml", JSON: manifestJSON(t, "prod", "a", `{"toCIDR":["10.0.0.0/24"]}`)}
	out := Reconcile(context.Background(), k, st, []Manifest{m}, true)
	if len(out) != 1 {
		t.Fatalf("out=%#v", out)
	}
	if !out[0].Applied || out[0].Error != "" {
		t.Fatalf("status=%#v, want applied", out[0])
	}
	hist := st.PolicyHistory("prod", "a", 10)
	var sawApply bool
	for _, r := range hist {
		if r.Action == "apply" && r.Actor == Actor {
			sawApply = true
		}
	}
	if !sawApply {
		t.Fatalf("expected an 'apply' revision recorded with actor=%q, history=%#v", Actor, hist)
	}
}

func TestReconcilePlanOnlyWhenAutoApplyFalse(t *testing.T) {
	k, fk := newFakeKube(t)
	st := store.New()
	m := Manifest{Path: "a.yaml", JSON: manifestJSON(t, "prod", "a", `{"toCIDR":["10.0.0.0/24"]}`)}
	out := Reconcile(context.Background(), k, st, []Manifest{m}, false)
	if out[0].Applied {
		t.Fatalf("status=%#v, must not apply when autoApply=false", out[0])
	}
	if out[0].Note == "" || !strings.Contains(out[0].Note, "AUTO_APPLY") {
		t.Fatalf("note=%q, want an explanatory note", out[0].Note)
	}
	fk.mu.Lock()
	_, exists := fk.policies["prod/a"]
	fk.mu.Unlock()
	if exists {
		t.Fatal("nothing should have been applied to the fake backend")
	}
}

func TestReconcileNeverAutoAppliesHighRisk(t *testing.T) {
	k, _ := newFakeKube(t)
	st := store.New()
	// An empty endpointSelector is flagged "critical" risk by AnalyzeChange.
	m := Manifest{Path: "a.yaml", JSON: []byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"a","namespace":"prod"},"spec":{"endpointSelector":{},"egress":[{"toCIDR":["10.0.0.0/24"]}]}}`)}
	out := Reconcile(context.Background(), k, st, []Manifest{m}, true)
	if out[0].Applied {
		t.Fatalf("status=%#v, must never auto-apply a critical-risk change", out[0])
	}
	if !strings.Contains(out[0].Note, "risk is") {
		t.Fatalf("note=%q, want a risk explanation", out[0].Note)
	}
}

func TestReconcileNoChangeIsInSync(t *testing.T) {
	k, fk := newFakeKube(t)
	st := store.New()
	body := manifestJSON(t, "prod", "a", `{"toCIDR":["10.0.0.0/24"]}`)
	fk.mu.Lock()
	fk.policies["prod/a"] = body
	fk.mu.Unlock()
	out := Reconcile(context.Background(), k, st, []Manifest{{Path: "a.yaml", JSON: body}}, true)
	if out[0].Applied {
		t.Fatalf("status=%#v, nothing changed, should not apply", out[0])
	}
	if out[0].Note != "in sync" {
		t.Fatalf("note=%q, want 'in sync'", out[0].Note)
	}
}

func TestReconcileDetectsDriftAndNeverAutoApplies(t *testing.T) {
	k, fk := newFakeKube(t)
	st := store.New()
	original := manifestJSON(t, "prod", "a", `{"toCIDR":["10.0.0.0/24"]}`)

	// First pass: GitOps applies the original manifest cleanly.
	first := Reconcile(context.Background(), k, st, []Manifest{{Path: "a.yaml", JSON: original}}, true)
	if !first[0].Applied {
		t.Fatalf("expected the first pass to apply cleanly: %#v", first[0])
	}

	// Someone hand-edits the live policy directly (not through GitOps).
	handEdited := manifestJSON(t, "prod", "a", `{"toCIDR":["10.0.0.0/24"],"toEntities":["world"]}`)
	fk.mu.Lock()
	fk.policies["prod/a"] = handEdited
	fk.mu.Unlock()

	// A new candidate manifest arrives from Git — must detect drift and
	// refuse to silently overwrite the hand-edit.
	candidate := manifestJSON(t, "prod", "a", `{"toCIDR":["10.0.2.0/24"]}`)
	second := Reconcile(context.Background(), k, st, []Manifest{{Path: "a.yaml", JSON: candidate}}, true)
	if !second[0].Drifted {
		t.Fatalf("expected drift to be detected: %#v", second[0])
	}
	if second[0].Applied {
		t.Fatal("a drifted policy must never be auto-applied over")
	}
}

func TestResyncBypassesDriftGating(t *testing.T) {
	k, _ := newFakeKube(t)
	st := store.New()
	candidate := manifestJSON(t, "prod", "a", `{"toCIDR":["10.0.0.0/24"]}`)
	plan, err := Resync(context.Background(), k, st, candidate, "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Risk == "" {
		t.Fatalf("plan=%#v", plan)
	}
}

func TestResyncRequiresConfirmedRiskForHighRisk(t *testing.T) {
	k, _ := newFakeKube(t)
	st := store.New()
	candidate := []byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"a","namespace":"prod"},"spec":{"endpointSelector":{},"egress":[{"toCIDR":["10.0.0.0/24"]}]}}`)
	if _, err := Resync(context.Background(), k, st, candidate, ""); err == nil {
		t.Fatal("expected an error without a confirmed risk for a critical-risk change")
	}
	if _, err := Resync(context.Background(), k, st, candidate, "critical"); err != nil {
		t.Fatalf("expected success with a matching confirmed risk: %v", err)
	}
}
