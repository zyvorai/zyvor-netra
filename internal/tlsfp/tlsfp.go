// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package tlsfp computes JA3 and JA4 TLS fingerprints from a single
// TLS ClientHello record, using only what Netra already parses.
//
// Constraints (Netra safety model):
//   - Reads a single egress skb. No stream reassembly. No decryption.
//   - Bounded memory: per-workload fingerprint sets are capped and LRU'd.
//   - Observe-only. Novel/fingerprint findings feed alerting/SIEM.
//
// References:
//
//	JA3: https://github.com/salesforce/ja3
//	JA4: https://github.com/FoxIO-LLC/ja4
package tlsfp

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrTruncated means the ClientHello is shorter than the parser needs.
var ErrTruncated = errors.New("tlsfp: truncated ClientHello")

// ErrNotClientHello means the record is not a TLS ClientHello.
var ErrNotClientHello = errors.New("tlsfp: not a ClientHello")

// Fingerprint is the parsed and derived metadata.
type Fingerprint struct {
	JA3     string   `json:"ja3"`
	JA3Raw  string   `json:"ja3Raw"`
	JA4     string   `json:"ja4"`
	Version uint16   `json:"version"` // negotiated legacy version from ClientHello
	SNI     string   `json:"sni,omitempty"`
	ALPN    string   `json:"alpn,omitempty"`
	Ciphers []uint16 `json:"ciphers"`
	Exts    []uint16 `json:"exts"`
	Curves  []uint16 `json:"curves"`
	SigAlgs []uint16 `json:"sigAlgs"`
	QUIC    bool     `json:"quic,omitempty"`
	ECH     bool     `json:"ech,omitempty"` // ClientHello carried encrypted_client_hello ext
}

const (
	recordTypeHandshake      = 22
	handshakeTypeClientHello = 1
	extServerName            = 0
	extALPN                  = 16
	extSupportedVersions     = 43
	extSignatureAlgorithms   = 13
	extSupportedGroups       = 10
	extECPointFormats        = 11
	extECH                   = 0xfe0d // encrypted_client_hello
)

// ParseClientHello parses a TLS record and returns a Fingerprint.
// Input may be truncated; the parser stops and returns what it has so
// long as the essential fields are present.
func ParseClientHello(data []byte) (*Fingerprint, error) {
	if len(data) < 6 {
		return nil, ErrTruncated
	}
	// TLS record header.
	if data[0] != recordTypeHandshake {
		return nil, ErrNotClientHello
	}
	recLen := int(data[3])<<8 | int(data[4])
	end := min(5+recLen, len(data))
	body := data[5:end]

	if len(body) < 4 {
		return nil, ErrTruncated
	}
	if body[0] != handshakeTypeClientHello {
		return nil, ErrNotClientHello
	}
	// body[1:4] is handshake length; we trust the record length above.

	p := &parser{buf: body, pos: 4}
	fp := &Fingerprint{}

	// legacy_version
	v, err := p.u16()
	if err != nil {
		return nil, err
	}
	fp.Version = v

	// random(32)
	if err := p.skip(32); err != nil {
		return nil, err
	}

	// session_id
	sidLen, err := p.u8()
	if err != nil {
		return nil, err
	}
	if err := p.skip(int(sidLen)); err != nil {
		return nil, err
	}

	// cipher_suites
	csLen, err := p.u16()
	if err != nil {
		return nil, err
	}
	if csLen%2 != 0 {
		return nil, fmt.Errorf("tlsfp: odd cipher suite length %d", csLen)
	}
	for i := 0; i < int(csLen); i += 2 {
		c, err := p.u16()
		if err != nil {
			break
		}
		fp.Ciphers = append(fp.Ciphers, c)
	}

	// compression_methods
	cmLen, err := p.u8()
	if err != nil {
		return nil, err
	}
	if err := p.skip(int(cmLen)); err != nil {
		return nil, err
	}

	// extensions (optional)
	if !p.has(2) {
		// Some ancient hellos have no extensions.
		finalize(fp)
		return fp, nil
	}
	extTotal, err := p.u16()
	if err != nil {
		return nil, err
	}
	extEnd := p.pos + int(extTotal)

	for p.pos+4 <= len(p.buf) && p.pos < extEnd {
		extType, err := p.u16()
		if err != nil {
			break
		}
		extLen, err := p.u16()
		if err != nil {
			break
		}
		if p.pos+int(extLen) > len(p.buf) {
			// Truncated extension — stop but keep what we have.
			fp.Exts = append(fp.Exts, extType)
			break
		}
		extData := p.buf[p.pos : p.pos+int(extLen)]
		fp.Exts = append(fp.Exts, extType)
		switch extType {
		case extServerName:
			fp.SNI = parseSNI(extData)
		case extALPN:
			if v := parseALPN(extData); v != "" {
				fp.ALPN = v
			}
		case extSupportedVersions:
			fp.Version = parseSupportedVersions(extData, fp.Version)
		case extSupportedGroups:
			fp.Curves = parseU16List(extData)
		case extSignatureAlgorithms:
			fp.SigAlgs = parseU16List(extData)
		case extECPointFormats:
			// Not needed for JA4 but useful for JA3.
			_ = parseU8List(extData)
		case extECH:
			fp.ECH = true
		}
		p.pos += int(extLen)
	}

	finalize(fp)
	return fp, nil
}

func finalize(fp *Fingerprint) {
	fp.JA3Raw = ja3String(fp)
	sum := md5.Sum([]byte(fp.JA3Raw))
	fp.JA3 = hex.EncodeToString(sum[:])
	fp.JA4 = ja4String(fp)
}

// ---------- JA3 ----------

func ja3String(fp *Fingerprint) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d,", fp.Version)
	writeU16Dash(&b, filterGREASE(fp.Ciphers))
	b.WriteByte(',')
	writeU16Dash(&b, filterGREASE(fp.Exts))
	b.WriteByte(',')
	writeU16Dash(&b, filterGREASE(fp.Curves))
	b.WriteByte(',')
	// JA3 does not use sig algs.
	return b.String()
}

func writeU16Dash(b *strings.Builder, xs []uint16) {
	for i, x := range xs {
		if i > 0 {
			b.WriteByte('-')
		}
		fmt.Fprintf(b, "%d", x)
	}
}

// ---------- JA4 ----------

func ja4String(fp *Fingerprint) string {
	a := ja4a(fp)
	b := ja4b(fp)
	c := ja4c(fp)
	return a + "_" + b + "_" + c
}

func ja4a(fp *Fingerprint) string {
	var b strings.Builder
	if fp.QUIC {
		b.WriteByte('q')
	} else {
		b.WriteByte('t')
	}
	b.WriteString(version2(fp.Version))
	if fp.SNI != "" && !isIP(fp.SNI) {
		b.WriteByte('d')
	} else {
		b.WriteByte('i')
	}
	fmt.Fprintf(&b, "%02d", min(len(filterGREASE(fp.Ciphers)), 99))
	fmt.Fprintf(&b, "%02d", min(len(filterGREASE(fp.Exts)), 99))
	b.WriteString(alpnCode(fp.ALPN))
	return b.String()
}

func ja4b(fp *Fingerprint) string {
	cs := filterGREASE(fp.Ciphers)
	slices.Sort(cs)
	var b strings.Builder
	for _, c := range cs {
		fmt.Fprintf(&b, "%04x,", c)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])[:12]
}

func ja4c(fp *Fingerprint) string {
	// Extensions excluding SNI and ALPN, sorted.
	exts := filterGREASE(fp.Exts)
	filtered := exts[:0:0]
	for _, e := range exts {
		if e == extServerName || e == extALPN {
			continue
		}
		filtered = append(filtered, e)
	}
	slices.Sort(filtered)

	var b strings.Builder
	for _, e := range filtered {
		fmt.Fprintf(&b, "%04x,", e)
	}
	b.WriteByte('_')
	sigs := filterGREASE(fp.SigAlgs)
	slices.Sort(sigs)
	for _, s := range sigs {
		fmt.Fprintf(&b, "%04x,", s)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])[:12]
}

func version2(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	default:
		return "00"
	}
}

func alpnCode(alpn string) string {
	if alpn == "" {
		return "00"
	}
	if len(alpn) == 1 {
		return strings.ToLower(alpn + alpn)
	}
	return strings.ToLower(string(alpn[0]) + string(alpn[len(alpn)-1]))
}

// ---------- helpers ----------

func filterGREASE(xs []uint16) []uint16 {
	out := make([]uint16, 0, len(xs))
	for _, x := range xs {
		if !isGREASE(x) {
			out = append(out, x)
		}
	}
	return out
}

// isGREASE reports whether v matches the GREASE pattern (0x0a0a, 0x1a1a, ...).
func isGREASE(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}

func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// list_len(2), type(1)=0, name_len(2), name
	// server_name_type
	if data[2] != 0 {
		return ""
	}
	l := int(data[3])<<8 | int(data[4])
	if 5+l > len(data) {
		return ""
	}
	return string(data[5 : 5+l])
}

func parseALPN(data []byte) string {
	if len(data) < 3 {
		return ""
	}
	// list_len(2)
	l := int(data[0])<<8 | int(data[1])
	if 2+l > len(data) {
		return ""
	}
	// first entry only: entry_len(1), entry
	p := data[2 : 2+l]
	if len(p) < 1 {
		return ""
	}
	el := int(p[0])
	if 1+el > len(p) {
		return ""
	}
	return string(p[1 : 1+el])
}

func parseSupportedVersions(data []byte, fallback uint16) uint16 {
	if len(data) < 1 {
		return fallback
	}
	l := int(data[0])
	if l == 0 || 1+l > len(data) {
		return fallback
	}
	// Pick the highest version we recognize.
	best := fallback
	for i := 1; i+1 < 1+l; i += 2 {
		v := uint16(data[i])<<8 | uint16(data[i+1])
		if v > best && v <= 0x0304 {
			best = v
		}
	}
	return best
}

func parseU16List(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	l := int(data[0])<<8 | int(data[1])
	if 2+l > len(data) {
		l = len(data) - 2
	}
	out := make([]uint16, 0, l/2)
	for i := 2; i+1 < 2+l; i += 2 {
		out = append(out, uint16(data[i])<<8|uint16(data[i+1]))
	}
	return out
}

func parseU8List(data []byte) []uint8 {
	if len(data) < 1 {
		return nil
	}
	l := int(data[0])
	if 1+l > len(data) {
		l = len(data) - 1
	}
	return append([]uint8(nil), data[1:1+l]...)
}

func isIP(s string) bool {
	// Cheap check: only digits, dots, colons, hex.
	hasDot := false
	hasColon := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		case c == '.':
			hasDot = true
		case c == ':':
			hasColon = true
		default:
			return false
		}
	}
	return hasDot || hasColon
}

type parser struct {
	buf []byte
	pos int
}

func (p *parser) has(n int) bool { return p.pos+n <= len(p.buf) }

func (p *parser) u8() (uint8, error) {
	if !p.has(1) {
		return 0, ErrTruncated
	}
	v := p.buf[p.pos]
	p.pos++
	return v, nil
}

func (p *parser) u16() (uint16, error) {
	if !p.has(2) {
		return 0, ErrTruncated
	}
	v := uint16(p.buf[p.pos])<<8 | uint16(p.buf[p.pos+1])
	p.pos += 2
	return v, nil
}

func (p *parser) skip(n int) error {
	if !p.has(n) {
		return ErrTruncated
	}
	p.pos += n
	return nil
}
