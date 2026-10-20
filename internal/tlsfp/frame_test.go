// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package tlsfp

import (
	"testing"
)

func TestExtractAndDetectFromFrame(t *testing.T) {
	hello := buildClientHello(helloOpts{
		version: 0x0303,
		ciphers: []uint16{0x1301, 0x1302},
		sni:     "example.com",
		alpn:    []string{"h2"},
	})
	// Build minimal Ethernet + IPv4 + TCP wrapping the hello.
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 6 // TCP
	tcp := make([]byte, 20)
	tcp[12] = 5 << 4 // data offset
	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00
	frame := append(append(append(eth, ip...), tcp...), hello...)

	got := ExtractClientHello(frame)
	if got == nil {
		t.Fatal("expected ClientHello payload")
	}
	d := NewDetector(10)
	d.ObserveFrame("n1", frame)
	snap := d.Snapshot(10)
	if len(snap) != 1 || snap[0].SNI != "example.com" || snap[0].JA3 == "" {
		t.Fatalf("%+v", snap)
	}
}

// A raw IPv4 packet whose source address is 8.0.x.x has 0x0800 at bytes
// 12-13 and used to be misparsed as Ethernet instead of reaching the raw-IP path.
func TestExtractClientHelloRawIPv4LooksLikeEthertype(t *testing.T) {
	hello := buildClientHello(helloOpts{version: 0x0303, ciphers: []uint16{0x1301}, sni: "example.com"})
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 6
	ip[12], ip[13] = 0x08, 0x00 // src 8.0.0.1
	ip[15] = 1
	tcp := make([]byte, 20)
	tcp[12] = 5 << 4
	pkt := append(append(ip, tcp...), hello...)
	if ExtractClientHello(pkt) == nil {
		t.Fatal("raw IPv4 with src 8.0.x.x not parsed")
	}
}
