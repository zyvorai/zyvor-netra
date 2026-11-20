//go:build linux

package procmeta

import "testing"

func TestCapsHas(t *testing.T) {
	// CAP_NET_RAW is bit 13.
	c := Caps{Eff: 1 << 13}
	if !c.Has("CAP_NET_RAW") {
		t.Error("CAP_NET_RAW should be present")
	}
	if c.Has("CAP_NET_ADMIN") {
		t.Error("CAP_NET_ADMIN should not be present")
	}
	if c.Has("CAP_NOT_REAL") {
		t.Error("unknown cap should return false")
	}
}

func TestCapsNames(t *testing.T) {
	c := Caps{Eff: 1<<10 | 1<<13} // BIND_SERVICE, NET_RAW
	names := c.Names()
	if len(names) != 2 || names[0] != "CAP_NET_BIND_SERVICE" || names[1] != "CAP_NET_RAW" {
		t.Errorf("Names = %v", names)
	}
}

func TestCapsNetworkRelevant(t *testing.T) {
	c := Caps{Eff: 1<<21 | 1<<12 | 1<<3} // SYS_ADMIN, NET_ADMIN, FOWNER
	got := c.NetworkRelevant()
	want := []string{"CAP_NET_ADMIN", "CAP_SYS_ADMIN"}
	if len(got) != len(want) {
		t.Fatalf("NetworkRelevant = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("NetworkRelevant[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCapsHasAny(t *testing.T) {
	c := Caps{Eff: 1 << 13}
	if !c.HasAny("CAP_NET_ADMIN", "CAP_NET_RAW") {
		t.Error("HasAny should find CAP_NET_RAW")
	}
	if c.HasAny("CAP_NET_ADMIN", "CAP_SYS_ADMIN") {
		t.Error("HasAny should return false")
	}
}

func TestCapsAllBitsRoundtrip(t *testing.T) {
	// Setting every bit 0..40 must produce all named capabilities.
	var c Caps
	for i := 0; i <= 40; i++ {
		c.Eff |= uint64(1) << uint(i)
	}
	names := c.Names()
	if len(names) != 41 {
		t.Errorf("Names len = %d, want 41", len(names))
	}
	if names[0] != "CAP_CHOWN" || names[40] != "CAP_CHECKPOINT_RESTORE" {
		t.Errorf("first/last = %q / %q", names[0], names[40])
	}
}
