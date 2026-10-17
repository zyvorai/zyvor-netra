// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package dnsdetect

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPersistRoundTrip(t *testing.T) {
	d := New(DefaultConfig())
	d.mu.Lock()
	d.findings[findingKey{ftype: FindingDGA, registered: "evil.test", namespace: "prod", pod: "api"}] = &Finding{
		ID: "1", Type: FindingDGA, Domain: "evil.test", Namespace: "prod", Pod: "api",
		FirstSeen: time.Now().UTC().Add(-time.Minute), LastSeen: time.Now().UTC(),
		Signals: []string{"entropy"},
	}
	d.mu.Unlock()

	path := filepath.Join(t.TempDir(), "dns.json")
	if err := d.SavePersist(path); err != nil {
		t.Fatal(err)
	}
	d2 := New(DefaultConfig())
	n, err := d2.LoadPersist(path)
	if err != nil || n != 1 {
		t.Fatalf("imported=%d err=%v", n, err)
	}
	if len(d2.Findings()) != 1 {
		t.Fatalf("findings=%d", len(d2.Findings()))
	}
}
