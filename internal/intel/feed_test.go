// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package intel

import "testing"

func TestFeedSetAndClear(t *testing.T) {
	f := &Feed{}
	prev, err := Parse("203.0.113.10\nmalware.example.com\n")
	if err != nil {
		t.Fatal(err)
	}
	st := f.Set(prev, "test", "unit")
	if st.Count != 2 || st.Empty {
		t.Fatalf("%+v", st)
	}
	if len(f.Entries()) != 2 {
		t.Fatalf("%d", len(f.Entries()))
	}
	st = f.Clear()
	if !st.Empty || st.Count != 0 {
		t.Fatalf("%+v", st)
	}
}
