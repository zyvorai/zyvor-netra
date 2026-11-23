// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package tlsposture builds a TLS client posture inventory from the JA4
// ClientHello fingerprints Netra already samples. It reads one field family
// only: the first JA4 segment, which carries the protocol (TCP or QUIC), the
// HIGHEST TLS version the client offers, whether it sent an SNI, the cipher
// and extension counts and the first ALPN value. There is no decryption, no
// certificate, no cipher list and no server side: a ClientHello shows what a
// client is willing to speak, not what was negotiated. Read-only.
package tlsposture

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

const (
	// MaxRows bounds the inventory rows returned.
	MaxRows = 500
	// MaxFindings bounds the findings returned.
	MaxFindings = 200
)

// Ja4A is the parsed first segment of a JA4 fingerprint.
type Ja4A struct {
	Proto   string `json:"proto"`   // tcp, quic, dtls
	Version string `json:"version"` // 1.3, 1.2, 1.1, 1.0, ssl3, ssl2, dtls1.0 ..., unknown
	SNI     bool   `json:"sni"`     // a domain SNI extension was present
	Ciphers int    `json:"ciphers"`
	Exts    int    `json:"extensions"`
	ALPN    string `json:"alpn,omitempty"`
	Legacy  bool   `json:"legacyMax"`
}

var versions = map[string]string{
	"13": "1.3", "12": "1.2", "11": "1.1", "10": "1.0", "s3": "ssl3", "s2": "ssl2",
	"d1": "dtls1.0", "d2": "dtls1.2", "d3": "dtls1.3",
}

// ParseJA4 parses the first segment of a JA4 string (the part before the
// first underscore). It never panics on malformed input; ok is false when
// the string is not a JA4 first segment.
func ParseJA4(ja4 string) (Ja4A, bool) {
	seg, _, _ := strings.Cut(strings.TrimSpace(ja4), "_")
	if len(seg) != 10 {
		return Ja4A{}, false
	}
	var out Ja4A
	switch seg[0] {
	case 't':
		out.Proto = "tcp"
	case 'q':
		out.Proto = "quic"
	case 'd':
		out.Proto = "dtls"
	default:
		return Ja4A{}, false
	}
	v, known := versions[seg[1:3]]
	if !known {
		if seg[1:3] != "00" {
			return Ja4A{}, false
		}
		v = "unknown"
	}
	out.Version = v
	switch seg[3] {
	case 'd':
		out.SNI = true
	case 'i':
	default:
		return Ja4A{}, false
	}
	c, ok1 := atoi2(seg[4:6])
	e, ok2 := atoi2(seg[6:8])
	if !ok1 || !ok2 {
		return Ja4A{}, false
	}
	out.Ciphers, out.Exts = c, e
	if a := seg[8:10]; a != "00" {
		out.ALPN = a
	}
	switch out.Version {
	case "1.1", "1.0", "ssl3", "ssl2", "dtls1.0":
		out.Legacy = true
	}
	return out, true
}

func atoi2(s string) (int, bool) {
	if len(s) != 2 || s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9' {
		return 0, false
	}
	return int(s[0]-'0')*10 + int(s[1]-'0'), true
}

// Row is one workload and SNI with the TLS versions its clients offered.
type Row struct {
	Namespace string            `json:"namespace,omitempty"`
	Workload  string            `json:"workload,omitempty"`
	Node      string            `json:"node,omitempty"`
	SNI       string            `json:"sni,omitempty"`
	Versions  map[string]uint64 `json:"versions"`
	Hellos    uint64            `json:"hellos"`
	ECH       uint64            `json:"ech,omitempty"`
	NoSNI     uint64            `json:"noSni,omitempty"`
	NoALPN    uint64            `json:"noAlpn,omitempty"`
	Unparsed  uint64            `json:"unparsed,omitempty"`
	LegacyMax uint64            `json:"legacyMax,omitempty"`
}

// Finding is a posture issue.
type Finding struct {
	Severity  string `json:"severity"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Workload  string `json:"workload,omitempty"`
	Node      string `json:"node,omitempty"`
	SNI       string `json:"sni,omitempty"`
	Hellos    uint64 `json:"hellos"`
	Message   string `json:"message"`
}

// Summary is the cluster-wide roll-up.
type Summary struct {
	Hellos        uint64            `json:"hellos"`
	Versions      map[string]uint64 `json:"versions"`
	TLS13Percent  float64           `json:"tls13Percent"`
	LegacyHellos  uint64            `json:"legacyMaxHellos"`
	ECH           uint64            `json:"ech"`
	QUIC          uint64            `json:"quic"`
	Unparsed      uint64            `json:"unparsed"`
	WorkloadsSeen int               `json:"workloadsSeen"`
}

// Result is the TLS posture inventory.
type Result struct {
	Summary   Summary   `json:"summary"`
	Rows      []Row     `json:"rows"`
	Findings  []Finding `json:"findings"`
	Truncated bool      `json:"truncated,omitempty"`
	Caveats   []string  `json:"caveats"`
}

// Caveats are returned with every result.
func Caveats() []string {
	return []string{
		"A ClientHello shows the HIGHEST TLS version a client offers, not the version negotiated. A client that offers TLS 1.3 may still be served TLS 1.2 by an old server; that needs the ServerHello, which is not collected.",
		"No certificate, chain, expiry or cipher-suite list is collected: Netra keeps the JA3/JA4 hash, the cipher and extension counts, the SNI and the ECH flag. TLS 1.3 encrypts the certificate, so a passive observer cannot read it.",
		"Fingerprints come from rate-limited single-packet samples, so absence is not proof a workload does not use a weak client. Counts are samples, not connection counts.",
		"Nothing is decrypted and no payload is read. Read-only.",
	}
}

type rowKey struct{ ns, wl, node, sni string }

// Build aggregates the per-workload JA4 samples reported by non-stale agents.
func Build(agents []models.AgentStatus) Result {
	rows := map[rowKey]*Row{}
	sum := Summary{Versions: map[string]uint64{}}
	workloads := map[string]struct{}{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, fp := range a.TLSFingerprints {
			n := fp.Count
			if n == 0 {
				n = 1
			}
			wl := fp.WorkloadName
			if wl == "" {
				wl = fp.Pod
			}
			k := rowKey{fp.Namespace, wl, a.Node, strings.ToLower(strings.TrimSpace(fp.SNI))}
			if len(k.sni) > 253 {
				k.sni = k.sni[:253]
			}
			r := rows[k]
			if r == nil {
				if len(rows) >= 20*MaxRows { // hard cap on aggregation work
					sum.Hellos += n
					sum.Unparsed += n
					continue
				}
				r = &Row{Namespace: k.ns, Workload: k.wl, Node: k.node, SNI: k.sni, Versions: map[string]uint64{}}
				rows[k] = r
			}
			workloads[k.ns+"/"+k.wl] = struct{}{}
			r.Hellos += n
			sum.Hellos += n
			if fp.ECH {
				r.ECH += n
				sum.ECH += n
			}
			p, ok := ParseJA4(fp.JA4)
			if !ok {
				r.Unparsed += n
				sum.Unparsed += n
				continue
			}
			r.Versions[p.Version] += n
			sum.Versions[p.Version] += n
			if p.Proto == "quic" {
				sum.QUIC += n
			}
			if !p.SNI {
				r.NoSNI += n
			}
			if p.ALPN == "" {
				r.NoALPN += n
			}
			if p.Legacy {
				r.LegacyMax += n
				sum.LegacyHellos += n
			}
		}
	}
	sum.WorkloadsSeen = len(workloads)
	if parsed := sum.Hellos - sum.Unparsed; parsed > 0 {
		sum.TLS13Percent = float64(int((float64(sum.Versions["1.3"])/float64(parsed))*1000+0.5)) / 10
	}
	res := Result{Summary: sum, Caveats: Caveats()}
	for _, r := range rows {
		res.Rows = append(res.Rows, *r)
		res.Findings = append(res.Findings, findings(*r)...)
	}
	sort.Slice(res.Rows, func(i, j int) bool {
		a, b := res.Rows[i], res.Rows[j]
		if a.LegacyMax != b.LegacyMax {
			return a.LegacyMax > b.LegacyMax
		}
		if a.Hellos != b.Hellos {
			return a.Hellos > b.Hellos
		}
		return a.Namespace+a.Workload+a.SNI < b.Namespace+b.Workload+b.SNI
	})
	if len(res.Rows) > MaxRows {
		res.Rows, res.Truncated = res.Rows[:MaxRows], true
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) > rank(b.Severity)
		}
		if a.Hellos != b.Hellos {
			return a.Hellos > b.Hellos
		}
		return a.Namespace+a.Workload+a.SNI+a.Kind < b.Namespace+b.Workload+b.SNI+b.Kind
	})
	if len(res.Findings) > MaxFindings {
		res.Findings, res.Truncated = res.Findings[:MaxFindings], true
	}
	if res.Rows == nil {
		res.Rows = []Row{}
	}
	if res.Findings == nil {
		res.Findings = []Finding{}
	}
	return res
}

func rank(s string) int {
	switch s {
	case "high":
		return 3
	case "warning":
		return 2
	}
	return 1
}

func findings(r Row) []Finding {
	base := Finding{Namespace: r.Namespace, Workload: r.Workload, Node: r.Node, SNI: r.SNI}
	var out []Finding
	add := func(sev, kind string, hellos uint64, msg string) {
		f := base
		f.Severity, f.Kind, f.Hellos, f.Message = sev, kind, hellos, msg
		out = append(out, f)
	}
	where := r.Workload
	if where == "" {
		where = "an unattributed process"
	}
	if r.SNI != "" {
		where += " to " + r.SNI
	}
	if n := r.Versions["ssl3"] + r.Versions["ssl2"]; n > 0 {
		add("high", "ssl-max-version", n, fmt.Sprintf("%s offers at most SSL 3.0 or older in %d sampled hello(s)", where, n))
	}
	if n := r.Versions["1.1"] + r.Versions["1.0"] + r.Versions["dtls1.0"]; n > 0 {
		add("warning", "legacy-max-version", n, fmt.Sprintf("%s offers at most TLS 1.1 in %d sampled hello(s): it cannot negotiate TLS 1.2 or newer", where, n))
	}
	if n := r.Versions["1.2"]; n > 0 && r.Versions["1.3"] == 0 {
		add("info", "tls12-max", n, fmt.Sprintf("%s offers at most TLS 1.2 (no TLS 1.3 offered in this sample)", where))
	}
	if r.Unparsed > 0 {
		add("info", "unparsed-fingerprint", r.Unparsed, fmt.Sprintf("%s has %d hello(s) whose JA4 could not be read", where, r.Unparsed))
	}
	return out
}
