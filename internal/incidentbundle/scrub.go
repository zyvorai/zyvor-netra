// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package incidentbundle

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// MaskMode says how IP addresses are pseudonymised inside a bundle.
type MaskMode string

const (
	MaskNone   MaskMode = "none"
	MaskIPs    MaskMode = "ips"    // every address becomes ip-<8 hex>, keyed HMAC, stable within the bundle
	MaskPrefix MaskMode = "prefix" // prefix-preserving: addresses sharing a prefix still do, same family
)

// ParseMask reads the mask_ips query value or CLI flag.
func ParseMask(v string) (MaskMode, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "off", "none":
		return MaskNone, true
	case "1", "true", "on", "ips", "yes":
		return MaskIPs, true
	case "prefix", "prefix-preserving":
		return MaskPrefix, true
	}
	return MaskNone, false
}

const (
	maxRawString = 4096 // bytes examined before clipping (bounds regex work)
	maxString    = 300  // bytes kept
)

// secretRule is one pattern that is never allowed to survive into a bundle.
type secretRule struct {
	name string
	re   *regexp.Regexp
}

// secretRules are shared by the scrubber (replace) and verify (fail closed).
var secretRules = []secretRule{
	{"private-key-block", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)},
	{"bearer-token", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)},
	{"aws-access-key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"github-token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)},
	{"slack-token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"basic-auth-header", regexp.MustCompile(`(?i)\bbasic\s+[A-Za-z0-9+/=]{12,}`)},
	{"credential-assignment", regexp.MustCompile(`(?i)\b(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|authorization|auth|credential|cookie|session[_-]?id)\b["']?\s*[=:]\s*["']?[^\s"',;&]{3,}`)},
	{"url-credentials", regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^/\s@]*@`)},
	{"url-query", regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>?#]*\?[^\s"'<>]*`)},
}

var (
	urlRe  = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,3})?\b`)
	ipv6Re = regexp.MustCompile(`(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f.]{0,45}(?:/\d{1,3})?`)
	hostRe = regexp.MustCompile(`^[A-Za-z0-9_.:\-\[\]*]{1,253}$`)
)

// Redactor scrubs strings and records what it did, so the bundle's redaction
// block states exactly what was removed or masked.
type Redactor struct {
	mode   MaskMode
	key    []byte
	counts map[string]int
	cache  map[string]string
}

// NewRedactor builds a Redactor. A nil key with masking on draws a random one.
func NewRedactor(mode MaskMode, key []byte) *Redactor {
	if mode == "" {
		mode = MaskNone
	}
	if mode != MaskNone && len(key) == 0 {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
	}
	return &Redactor{mode: mode, key: key, counts: map[string]int{}, cache: map[string]string{}}
}

// KeyID names the masking key without revealing it, so two bundles can be
// recognised as masked with the same key (and so diff cleanly).
func (r *Redactor) KeyID() string {
	if r.mode == MaskNone {
		return ""
	}
	sum := sha256.Sum256(append([]byte("netra-incident-mask-key/1:"), r.key...))
	return hex.EncodeToString(sum[:4])
}

func (r *Redactor) note(rule string) { r.counts[rule]++ }

// Applied lists the rules that fired, with counts, sorted by name.
func (r *Redactor) Applied() []AppliedRule {
	out := make([]AppliedRule, 0, len(r.counts))
	for k, v := range r.counts {
		out = append(out, AppliedRule{Rule: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}

// String scrubs one free-text value: control characters, URL credentials and
// query strings, secret-looking assignments and tokens, clipping, and (when
// masking) IP addresses.
func (r *Redactor) String(s string) string {
	if s == "" {
		return s
	}
	if len(s) > maxRawString {
		s = strings.ToValidUTF8(s[:maxRawString], "")
		r.note("clipped")
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
		r.note("invalid-utf8")
	}
	changed := false
	s = strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			changed = true
			return ' '
		}
		return c
	}, s)
	if changed {
		r.note("control-characters")
	}
	s = urlRe.ReplaceAllStringFunc(s, r.cleanURL)
	for _, rule := range secretRules {
		if rule.name == "url-query" || rule.name == "url-credentials" {
			continue // handled structurally by cleanURL
		}
		if rule.re.MatchString(s) {
			n := len(rule.re.FindAllStringIndex(s, -1))
			r.counts[rule.name] += n
			s = rule.re.ReplaceAllString(s, "[redacted]")
		}
	}
	if r.mode != MaskNone {
		s = r.maskIPs(s)
	}
	if len(s) > maxString {
		cut := maxString
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
		r.note("clipped")
	}
	return s
}

// cleanURL keeps scheme, host and path of a URL and drops userinfo, query and
// fragment, which are where credentials and tokens travel.
func (r *Redactor) cleanURL(raw string) string {
	trail := ""
	for len(raw) > 0 && strings.ContainsRune(".,;)]}", rune(raw[len(raw)-1])) {
		trail = raw[len(raw)-1:] + trail
		raw = raw[:len(raw)-1]
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		r.note("unparseable-url")
		return "[redacted-url]" + trail
	}
	if u.User != nil {
		r.note("url-credentials")
	}
	if u.RawQuery != "" || strings.Contains(raw, "?") {
		r.note("url-query")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		r.note("url-fragment")
	}
	return u.Scheme + "://" + u.Host + u.EscapedPath() + trail
}

// Host validates a name the product exposes as a hostname (SNI, DNS name,
// HTTP Host). Anything else, such as a value carrying userinfo, a path or
// spaces, is replaced.
func (r *Redactor) Host(s string) string {
	if s == "" {
		return s
	}
	if !hostRe.MatchString(s) {
		r.note("invalid-hostname")
		return "[invalid-hostname]"
	}
	return r.String(s)
}

func (r *Redactor) maskIPs(s string) string {
	s = ipv4Re.ReplaceAllStringFunc(s, r.maskToken)
	return ipv6Re.ReplaceAllStringFunc(s, r.maskToken)
}

func (r *Redactor) maskToken(tok string) string {
	addrPart, suffix := tok, ""
	if i := strings.IndexByte(tok, '/'); i >= 0 {
		addrPart, suffix = tok[:i], tok[i:]
	}
	a, err := netip.ParseAddr(addrPart)
	if err != nil {
		return tok
	}
	key := a.String()
	if v, ok := r.cache[key]; ok {
		return v + suffix
	}
	var out string
	if r.mode == MaskPrefix {
		out = r.prefixPreserve(a).String()
	} else {
		mac := hmac.New(sha256.New, r.key)
		mac.Write([]byte(key))
		out = "ip-" + hex.EncodeToString(mac.Sum(nil)[:4])
	}
	r.cache[key] = out
	r.note("ip-masked")
	return out + suffix
}

// prefixPreserve is a Crypto-PAn style mapping: bit i of the output is bit i
// of the input XOR a keyed PRF of the first i input bits, so two addresses
// share an n-bit prefix in the output exactly when they do in the input.
func (r *Redactor) prefixPreserve(a netip.Addr) netip.Addr {
	a = a.Unmap()
	in := a.AsSlice()
	out := make([]byte, len(in))
	for i := 0; i < len(in)*8; i++ {
		mac := hmac.New(sha256.New, r.key)
		mac.Write([]byte{byte(len(in)), byte(i)})
		n := i / 8
		buf := append([]byte(nil), in[:n+1]...)
		buf[n] &= byte(0xff << (8 - i%8))
		mac.Write(buf)
		flip := mac.Sum(nil)[0] & 1
		bit := (in[i/8] >> (7 - i%8)) & 1
		out[i/8] |= (bit ^ flip) << (7 - i%8)
	}
	res, _ := netip.AddrFromSlice(out)
	return res
}

// Tree scrubs every string in a decoded JSON tree in place and returns it.
func (r *Redactor) Tree(v any) any {
	switch t := v.(type) {
	case string:
		return r.String(t)
	case []any:
		for i := range t {
			t[i] = r.Tree(t[i])
		}
		return t
	case map[string]any:
		for k, x := range t {
			t[k] = r.Tree(x)
		}
		return t
	}
	return v
}

// forbiddenKeys are field names that must never appear in a bundle section:
// they are what payload, credential or process-argument data would be called.
var forbiddenKeys = map[string]bool{
	"payload": true, "body": true, "packet": true, "packetsraw": true, "pcap": true, "rawbytes": true, "raw": true,
	"cmdline": true, "argv": true, "args": true, "environ": true, "env": true, "environment": true,
	"password": true, "passwd": true, "secret": true, "secrets": true, "token": true, "apikey": true, "api_key": true,
	"authorization": true, "cookie": true, "setcookie": true, "headers": true, "header": true, "query": true,
	"userinfo": true, "privatekey": true, "credentials": true, "credential": true, "content": true, "data": true,
}

func forbiddenKey(k string) bool {
	k = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, "-", ""), "_", ""))
	if forbiddenKeys[k] {
		return true
	}
	return forbiddenKeys[strings.ToLower(k)]
}

var blobRe = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{80,}$`)

// scanString returns the problems a string would cause in a shipped bundle.
func scanString(s string) []string {
	var out []string
	for _, rule := range secretRules {
		if rule.re.MatchString(s) {
			out = append(out, "secret-looking string ("+rule.name+")")
		}
	}
	if len(s) > maxString+3 {
		out = append(out, "string longer than the redaction clip")
	}
	if blobRe.MatchString(s) {
		out = append(out, "opaque encoded blob")
	}
	return out
}
