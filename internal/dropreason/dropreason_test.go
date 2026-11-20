// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package dropreason

import "testing"

func TestName(t *testing.T) {
	cases := []struct {
		reason uint32
		want   string
	}{
		{0, "not-specified"},
		{2, "no-socket"},
		{7, "netfilter-drop"},
		{9, "ip-csum"},
	}
	for _, c := range cases {
		if got := Name(c.reason); got != c.want {
			t.Errorf("Name(%d) = %q, want %q", c.reason, got, c.want)
		}
	}
}

func TestName_UnknownFallsBack(t *testing.T) {
	got := Name(999999)
	want := "reason #999999"
	if got != want {
		t.Errorf("Name(999999) = %q, want %q", got, want)
	}
}
