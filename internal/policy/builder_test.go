package policy

import (
	"github.com/zyvorai/netra/internal/models"
	"strings"
	"testing"
)

func TestBuildFQDN(t *testing.T) {
	b, err := Build(models.BuildPolicyRequest{Name: "x", Namespace: "payments", Selector: map[string]string{"app": "pay"}, Kind: "fqdn", To: []string{"api.example.com"}, Port: 443, IncludeDNS: true})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "toFQDNs") || !strings.Contains(s, "kube-dns") {
		t.Fatal(s)
	}
}
func TestEmptySelectorRejected(t *testing.T) {
	if _, err := Build(models.BuildPolicyRequest{Name: "x", Kind: "entity", To: []string{"world"}}); err == nil {
		t.Fatal("expected rejection")
	}
}
