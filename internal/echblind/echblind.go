// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package echblind flags TLS-looking egress where hostname visibility is
// missing (no SNI) or destinations are known ECH-capable CDNs. Observe-only;
// no decryption.
package echblind

import (
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/tlsfp"
)

// Finding is one blindness / ECH-related observation.
type Finding struct {
	Kind      string `json:"kind"` // missing-sni | ech-cdn | ech-hello
	HostOrIP  string `json:"hostOrIp,omitempty"`
	Node      string `json:"node,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Packets   uint64 `json:"packets,omitempty"`
	Severity  string `json:"severity"`
	Rationale string `json:"rationale"`
}

// Result is GET /api/v1/insights/ech-blind.
type Result struct {
	Findings   []Finding `json:"findings"`
	Count      int       `json:"count"`
	MissingSNI int       `json:"missingSni"`
	ECHCDN     int       `json:"echCdn"`
	ECHHello   int       `json:"echHello"`
	Capped     bool      `json:"capped"`
	Note       string    `json:"note"`
}

const MaxFindings = 300

// KnownECHCDNs are host suffixes commonly offering Encrypted Client Hello.
func KnownECHCDNs() []string {
	return []string{
		"cloudflare.com", "cloudflare-dns.com", "cloudflare.net",
		"fastly.net", "fastlylb.net",
		"akamai.net", "akamaiedge.net", "edgekey.net",
		"cdn.cloudflare.net",
	}
}

// Build merges agent metadata + optional tlsfp snapshot.
func Build(agents []models.AgentStatus, fps []tlsfp.Observation, limit int) Result {
	if limit <= 0 || limit > MaxFindings {
		limit = MaxFindings
	}
	out := Result{
		Findings: []Finding{},
		Note:     "Observe-only ECH / missing-SNI board. No decrypt. Pair with encrypted-dns + tls-fingerprints.",
	}
	echCDN := KnownECHCDNs()

	// HTTPS connect attempts without any matching SNI for that cgroup/workload.
	type wlKey struct{ ns, pod string }
	sniByWL := map[wlKey]uint64{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, t := range a.TLSMetadata {
			if strings.TrimSpace(t.SNI) != "" {
				sniByWL[wlKey{t.Namespace, t.Pod}] += t.Handshakes
			}
		}
	}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, c := range a.ConnectionAttempts {
			if c.RemotePort != 443 && c.RemotePort != 8443 {
				continue
			}
			k := wlKey{c.Namespace, c.Pod}
			if sniByWL[k] > 0 {
				continue
			}
			if c.Attempts == 0 {
				continue
			}
			out.MissingSNI++
			if len(out.Findings) < limit {
				out.Findings = append(out.Findings, Finding{
					Kind: "missing-sni", HostOrIP: c.RemoteIP, Node: a.Node,
					Namespace: c.Namespace, Pod: c.Pod, Packets: c.Attempts,
					Severity:  "medium",
					Rationale: "TLS-port connect attempts with no observed SNI for this workload (ECH, IP-literal, or truncated ClientHello)",
				})
			}
		}
		for _, t := range a.TLSMetadata {
			host := strings.ToLower(strings.TrimSuffix(t.SNI, "."))
			if host == "" {
				continue
			}
			for _, suf := range echCDN {
				if host == suf || strings.HasSuffix(host, "."+suf) {
					out.ECHCDN++
					if len(out.Findings) < limit {
						out.Findings = append(out.Findings, Finding{
							Kind: "ech-cdn", HostOrIP: host, Node: a.Node,
							Namespace: t.Namespace, Pod: t.Pod, Packets: t.Handshakes,
							Severity:  "info",
							Rationale: "Destination is a known ECH-capable CDN/provider suffix",
						})
					}
					break
				}
			}
		}
	}
	for _, o := range fps {
		if !o.ECH {
			continue
		}
		out.ECHHello++
		if len(out.Findings) < limit {
			out.Findings = append(out.Findings, Finding{
				Kind: "ech-hello", HostOrIP: o.SNI, Node: o.Node, Packets: o.Count,
				Severity:  "high",
				Rationale: "ClientHello carried encrypted_client_hello (0xfe0d) — SNI may be opaque",
			})
		}
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		return sev(out.Findings[i].Severity) > sev(out.Findings[j].Severity)
	})
	if len(out.Findings) >= limit {
		out.Capped = true
		out.Findings = out.Findings[:limit]
	}
	out.Count = len(out.Findings)
	return out
}

func sev(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
