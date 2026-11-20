// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package tlsfp

import (
	"strings"
	"testing"
)

// helloOpts configures a synthetically-built ClientHello, so tests don't
// depend on a hand-typed hex fixture (lengths in a TLS record are
// notoriously easy to get subtly wrong by hand).
type helloOpts struct {
	version      uint16
	ciphers      []uint16
	sni          string
	alpn         []string
	groups       []uint16
	sigAlgs      []uint16
	suppVersions []uint16
	ech          bool
	noExtensions bool
}

func u16be(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func extension(typ uint16, data []byte) []byte {
	out := u16be(typ)
	out = append(out, u16be(uint16(len(data)))...)
	return append(out, data...)
}

func buildClientHello(o helloOpts) []byte {
	var body []byte
	body = append(body, u16be(o.version)...)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session_id length = 0

	var ciphers []byte
	for _, c := range o.ciphers {
		ciphers = append(ciphers, u16be(c)...)
	}
	body = append(body, u16be(uint16(len(ciphers)))...)
	body = append(body, ciphers...)

	body = append(body, 1, 0) // compression methods: len=1, null

	if !o.noExtensions {
		var exts []byte
		if o.sni != "" {
			nameList := append([]byte{0}, u16be(uint16(len(o.sni)))...)
			nameList = append(nameList, []byte(o.sni)...)
			sniExt := append(u16be(uint16(len(nameList))), nameList...)
			exts = append(exts, extension(extServerName, sniExt)...)
		}
		if len(o.alpn) > 0 {
			var protoList []byte
			for _, p := range o.alpn {
				protoList = append(protoList, byte(len(p)))
				protoList = append(protoList, []byte(p)...)
			}
			alpnExt := append(u16be(uint16(len(protoList))), protoList...)
			exts = append(exts, extension(extALPN, alpnExt)...)
		}
		if len(o.groups) > 0 {
			var list []byte
			for _, g := range o.groups {
				list = append(list, u16be(g)...)
			}
			groupsExt := append(u16be(uint16(len(list))), list...)
			exts = append(exts, extension(extSupportedGroups, groupsExt)...)
		}
		if len(o.sigAlgs) > 0 {
			var list []byte
			for _, s := range o.sigAlgs {
				list = append(list, u16be(s)...)
			}
			sigExt := append(u16be(uint16(len(list))), list...)
			exts = append(exts, extension(extSignatureAlgorithms, sigExt)...)
		}
		if len(o.suppVersions) > 0 {
			list := []byte{byte(len(o.suppVersions) * 2)}
			for _, v := range o.suppVersions {
				list = append(list, u16be(v)...)
			}
			exts = append(exts, extension(extSupportedVersions, list)...)
		}
		if o.ech {
			// encrypted_client_hello (0xfe0d) — opaque payload is enough for the flag.
			exts = append(exts, extension(extECH, []byte{0x00, 0x00, 0x01, 0x00})...)
		}
		body = append(body, u16be(uint16(len(exts)))...)
		body = append(body, exts...)
	}

	handshake := append([]byte{handshakeTypeClientHello}, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	record := []byte{recordTypeHandshake, 0x03, 0x01}
	record = append(record, u16be(uint16(len(handshake)))...)
	record = append(record, handshake...)
	return record
}

func TestParseClientHelloFields(t *testing.T) {
	data := buildClientHello(helloOpts{
		version:      0x0303,
		ciphers:      []uint16{0x0a0a, 0x1301, 0x1302, 0xc02b},
		sni:          "cloudflare.com",
		alpn:         []string{"h2", "http/1.1"},
		groups:       []uint16{0x001d, 0x0017},
		sigAlgs:      []uint16{0x0804, 0x0503},
		suppVersions: []uint16{0x0304, 0x0303},
	})

	fp, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if fp.SNI != "cloudflare.com" {
		t.Errorf("SNI = %q, want cloudflare.com", fp.SNI)
	}
	if fp.ALPN != "h2" {
		t.Errorf("ALPN = %q, want h2 (first entry only)", fp.ALPN)
	}
	if fp.Version != 0x0304 {
		t.Errorf("version = 0x%04x, want 0x0304 (from supported_versions)", fp.Version)
	}
	if len(fp.Ciphers) != 4 {
		t.Fatalf("ciphers = %v, want 4 entries (GREASE included pre-filter)", fp.Ciphers)
	}
	if len(fp.Curves) != 2 {
		t.Errorf("curves = %v, want 2", fp.Curves)
	}
	if len(fp.SigAlgs) != 2 {
		t.Errorf("sigAlgs = %v, want 2", fp.SigAlgs)
	}
	if fp.JA3 == "" || len(fp.JA3) != 32 {
		t.Errorf("JA3 = %q, want a 32-char md5 hex digest", fp.JA3)
	}
	parts := strings.Split(fp.JA4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 = %q, want 3 underscore-separated parts", fp.JA4)
	}
	// JA4_a layout: t/q(1) + version(2) + d/i(1) + cipher-count(2) + ext-count(2) + alpn(2).
	// GREASE cipher (0x0a0a) must not count toward the cipher count.
	if got := parts[0][4:6]; got != "03" {
		t.Errorf("JA4_a cipher count = %q, want 03 (GREASE filtered out of 4)", got)
	}
}

func TestParseClientHelloRejectsShortInput(t *testing.T) {
	if _, err := ParseClientHello([]byte{0x01, 0x02}); err != ErrTruncated {
		t.Errorf("err = %v, want ErrTruncated", err)
	}
}

func TestParseClientHelloRejectsNonHandshake(t *testing.T) {
	// TLS record type 0x17 = application data, not a handshake.
	if _, err := ParseClientHello([]byte{0x17, 0x03, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00}); err != ErrNotClientHello {
		t.Errorf("err = %v, want ErrNotClientHello", err)
	}
}

func TestParseClientHelloRejectsNonClientHelloHandshake(t *testing.T) {
	data := buildClientHello(helloOpts{version: 0x0303, ciphers: []uint16{0x1301}})
	// Flip the handshake type byte (first byte of the handshake body,
	// at offset 5 in the record) away from ClientHello(1).
	data[5] = 2 // ServerHello
	if _, err := ParseClientHello(data); err != ErrNotClientHello {
		t.Errorf("err = %v, want ErrNotClientHello", err)
	}
}

func TestParseClientHelloWithNoExtensions(t *testing.T) {
	data := buildClientHello(helloOpts{version: 0x0301, ciphers: []uint16{0x002f}, noExtensions: true})
	fp, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if fp.SNI != "" || fp.ALPN != "" {
		t.Errorf("expected no SNI/ALPN, got %+v", fp)
	}
	if fp.JA3 == "" {
		t.Error("expected a JA3 hash even with no extensions")
	}
}

func TestParseClientHelloTruncatedMidExtensions(t *testing.T) {
	data := buildClientHello(helloOpts{
		version: 0x0303,
		ciphers: []uint16{0x1301, 0x1302},
		sni:     "example.com",
		alpn:    []string{"h2"},
	})
	// Cut the record off partway through the extension block. The parser
	// must return a partial-but-valid Fingerprint, not an error, since
	// ciphers/version were already fully parsed by that point.
	fp, err := ParseClientHello(data[:len(data)-5])
	if err != nil {
		t.Fatalf("expected a partial result, got error: %v", err)
	}
	if fp.Version != 0x0303 {
		t.Errorf("version = 0x%04x, want 0x0303", fp.Version)
	}
	if len(fp.Ciphers) != 2 {
		t.Errorf("ciphers = %v, want 2 (parsed before truncation point)", fp.Ciphers)
	}
}

func TestGREASEFilter(t *testing.T) {
	in := []uint16{0x0a0a, 0x1301, 0x1a1a, 0x1302, 0xfafa}
	out := filterGREASE(in)
	want := []uint16{0x1301, 0x1302}
	if len(out) != len(want) {
		t.Fatalf("filterGREASE(%v) = %v, want %v", in, out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("filterGREASE(%v)[%d] = 0x%04x, want 0x%04x", in, i, out[i], want[i])
		}
	}
}

func TestIsGREASE(t *testing.T) {
	cases := map[uint16]bool{
		0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0xfafa: true,
		0x1301: false, 0x0017: false, 0x0000: false,
	}
	for v, want := range cases {
		if got := isGREASE(v); got != want {
			t.Errorf("isGREASE(0x%04x) = %v, want %v", v, got, want)
		}
	}
}

func TestIsIP(t *testing.T) {
	cases := map[string]bool{
		"1.2.3.4":        true,
		"::1":            true,
		"2001:db8::1":    true,
		"example.com":    false,
		"cloudflare.com": false,
	}
	for in, want := range cases {
		if got := isIP(in); got != want {
			t.Errorf("isIP(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestJA3AndJA4AreDeterministic(t *testing.T) {
	data := buildClientHello(helloOpts{
		version: 0x0303,
		ciphers: []uint16{0x1301, 0x1302, 0xc02b},
		sni:     "example.com",
		alpn:    []string{"h2"},
		groups:  []uint16{0x001d},
	})
	fp1, err1 := ParseClientHello(data)
	fp2, err2 := ParseClientHello(data)
	if err1 != nil || err2 != nil {
		t.Fatalf("ParseClientHello errors: %v, %v", err1, err2)
	}
	if fp1.JA3 != fp2.JA3 || fp1.JA4 != fp2.JA4 {
		t.Fatalf("fingerprints not deterministic: (%s,%s) vs (%s,%s)", fp1.JA3, fp1.JA4, fp2.JA3, fp2.JA4)
	}
}

func TestJA4DistinguishesDomainFromIPSNI(t *testing.T) {
	domain := buildClientHello(helloOpts{version: 0x0303, ciphers: []uint16{0x1301}, sni: "example.com"})
	ip := buildClientHello(helloOpts{version: 0x0303, ciphers: []uint16{0x1301}, sni: "1.2.3.4"})
	fpDomain, err := ParseClientHello(domain)
	if err != nil {
		t.Fatal(err)
	}
	fpIP, err := ParseClientHello(ip)
	if err != nil {
		t.Fatal(err)
	}
	if fpDomain.JA4[3] != 'd' {
		t.Errorf("JA4_a[3] for domain SNI = %q, want 'd'", string(fpDomain.JA4[3]))
	}
	if fpIP.JA4[3] != 'i' {
		t.Errorf("JA4_a[3] for IP SNI = %q, want 'i'", string(fpIP.JA4[3]))
	}
}

func TestVersion2(t *testing.T) {
	cases := map[uint16]string{
		0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x9999: "00",
	}
	for v, want := range cases {
		if got := version2(v); got != want {
			t.Errorf("version2(0x%04x) = %q, want %q", v, got, want)
		}
	}
}

func TestAlpnCode(t *testing.T) {
	cases := map[string]string{
		"":         "00",
		"h":        "hh",
		"h2":       "h2",
		"http/1.1": "h1",
	}
	for in, want := range cases {
		if got := alpnCode(in); got != want {
			t.Errorf("alpnCode(%q) = %q, want %q", in, got, want)
		}
	}
}
