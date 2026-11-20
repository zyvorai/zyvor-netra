// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package policy

import (
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestLockdownPolicy(t *testing.T) {
	b, err := Lockdown(models.LockdownRequest{
		Namespace: "payments",
		Name:      "checkout",
		Kind:      "pod",
		Selector:  map[string]string{"app": "checkout"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "netra-lockdown-checkout") {
		t.Fatal(s)
	}
	if !strings.Contains(s, `"ingress": []`) && !strings.Contains(s, `"ingress":[]`) {
		t.Fatal("expected empty ingress", s)
	}
	if !strings.Contains(s, "kube-dns") {
		t.Fatal(s)
	}
}

func TestRecommendedSelectorPreferApp(t *testing.T) {
	sel := RecommendedSelector(map[string]string{
		"app":               "web",
		"pod-template-hash": "abc",
	}, "pod", "web-1")
	if sel["app"] != "web" || len(sel) != 1 {
		t.Fatalf("%v", sel)
	}
}

func TestPolicyMatchesLabels(t *testing.T) {
	cnp := []byte(`{"spec":{"endpointSelector":{"matchLabels":{"app":"web"}}}}`)
	if !PolicyMatchesLabels(cnp, map[string]string{"app": "web", "x": "1"}) {
		t.Fatal("expected match")
	}
	if PolicyMatchesLabels(cnp, map[string]string{"app": "other"}) {
		t.Fatal("expected miss")
	}
}

func TestLockdownPolicyName(t *testing.T) {
	if got := LockdownPolicyName("Checkout_API"); got != "netra-lockdown-checkout-api" {
		t.Fatalf("got %q", got)
	}
	long := strings.Repeat("a", 80)
	got := LockdownPolicyName(long)
	if len(got) > 63 {
		t.Fatalf("name too long: %d %q", len(got), got)
	}
	if !strings.HasPrefix(got, "netra-lockdown-") {
		t.Fatalf("got %q", got)
	}
	if strings.HasSuffix(got, "-") {
		t.Fatalf("trailing hyphen: %q", got)
	}
}

func TestSummarizeMatchingPolicies(t *testing.T) {
	list := []byte(`{
  "items": [
    {"metadata":{"name":"allow-web","namespace":"default"},"spec":{"endpointSelector":{"matchLabels":{"app":"web"}}}},
    {"metadata":{"name":"netra-lockdown-web","namespace":"default"},"spec":{"endpointSelector":{"matchLabels":{"app":"web"}}}},
    {"metadata":{"name":"other","namespace":"default"},"spec":{"endpointSelector":{"matchLabels":{"app":"db"}}}}
  ]
}`)
	refs := SummarizeMatchingPolicies(list, "default", map[string]string{"app": "web"})
	if len(refs) != 2 {
		t.Fatalf("got %#v", refs)
	}
	var sawLockdown bool
	for _, r := range refs {
		if r.Name == "netra-lockdown-web" {
			if !r.Lockdown {
				t.Fatal("expected lockdown flag")
			}
			sawLockdown = true
		}
		if r.Name == "allow-web" && r.Lockdown {
			t.Fatal("allow-web should not be lockdown")
		}
	}
	if !sawLockdown {
		t.Fatal("missing lockdown policy")
	}
}
