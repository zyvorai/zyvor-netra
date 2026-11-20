//go:build linux

package procmeta

import (
	"testing"
	"time"
)

func TestBootTime(t *testing.T) {
	b, err := BootTime()
	if err != nil {
		t.Fatal(err)
	}
	if b.After(time.Now()) {
		t.Errorf("boot time %v is in the future", b)
	}
	if b.Before(time.Unix(0, 0)) {
		t.Errorf("boot time %v predates the epoch", b)
	}
}

func TestBootTimeStable(t *testing.T) {
	a, err := BootTime()
	if err != nil {
		t.Fatal(err)
	}
	b, err := BootTime()
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Errorf("boot time changed between reads: %v vs %v", a, b)
	}
}
