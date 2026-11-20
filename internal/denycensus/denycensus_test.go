package denycensus

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestCountsWithoutListing(t *testing.T) {
	c := Build(models.EBPFFastPathConfig{Mode: "observe", BlockedIPv4: []string{"1.1.1.1", "8.8.8.8"}, BlockedDNS: []string{"bad.example"}}, time.Now())
	if c.BlockedIPv4 != 2 || c.TotalDenied != 3 || c.Mode != "observe" {
		t.Fatalf("%#v", c)
	}
}
