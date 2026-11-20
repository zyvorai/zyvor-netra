// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package models

import "testing"

func TestNormalizeCaptureBackend(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", CaptureBackendEBPF, false},
		{"ebpf", CaptureBackendEBPF, false},
		{"afpacket", CaptureBackendAFPacket, false},
		{"AFPACKET", "", true},
		{"bogus", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeCaptureBackend(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeCaptureBackend(%q): expected error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeCaptureBackend(%q): unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("NormalizeCaptureBackend(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
