// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package encdns flags encrypted-DNS usage from existing Netra metadata:
// destination port 853 (DoT) and known DoH SaaS hostnames (SNI/Host/DNS).
// No payloads, no decryption.
package encdns

import (
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

// Kind is dot | doh.
type Kind string

const (
	KindDoT Kind = "dot"
	KindDoH Kind = "doh"
)

// Hit is one observe-only encrypted-DNS sighting.
type Hit struct {
	Kind      Kind   `json:"kind"`
	Host      string `json:"host,omitempty"`
	DestIP    string `json:"destinationIp,omitempty"`
	Port      uint16 `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Node      string `json:"node,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Packets   uint64 `json:"packets,omitempty"`
	Label     string `json:"label,omitempty"`
}

// Result is the API envelope.
type Result struct {
	Hits    []Hit `json:"hits"`
	Count   int   `json:"count"`
	DoT     int   `json:"dotCount"`
	DoH     int   `json:"dohCount"`
	Capped  bool  `json:"capped"`
	Catalog int   `json:"dohCatalogSize"`
}

const MaxHits = 500

// DefaultDoHHosts are well-known public DoH endpoints (hostname suffixes).
func DefaultDoHHosts() []struct{ Suffix, Label string } {
	return []struct{ Suffix, Label string }{
		{"cloudflare-dns.com", "Cloudflare DoH"},
		{"one.one.one.one", "Cloudflare 1.1.1.1"},
		{"dns.google", "Google DoH"},
		{"dns.google.com", "Google DoH"},
		{"dns.quad9.net", "Quad9 DoH"},
		{"dns.nextdns.io", "NextDNS"},
		{"mozilla.cloudflare-dns.com", "Mozilla DoH"},
		{"doh.opendns.com", "OpenDNS DoH"},
		{"doh.cleanbrowsing.org", "CleanBrowsing"},
		{"dns.adguard.com", "AdGuard DoH"},
		{"doh.dns.sb", "DNS.SB"},
	}
}

// Match scans agent destination stats, connection attempts, and L7 metadata.
func Match(agents []models.AgentStatus, limit int) Result {
	if limit <= 0 || limit > MaxHits {
		limit = MaxHits
	}
	catalog := DefaultDoHHosts()
	out := Result{Hits: []Hit{}, Catalog: len(catalog)}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, st := range a.Stats {
			if out.Count >= limit {
				out.Capped = true
				return finalize(out)
			}
			if st.Port == 853 {
				out.Hits = append(out.Hits, Hit{
					Kind: KindDoT, DestIP: st.DestinationIP, Port: 853, Protocol: st.Protocol,
					Node: a.Node, Namespace: st.Namespace, Pod: st.Pod, Packets: st.Packets,
					Label: "DNS-over-TLS (port 853)",
				})
				out.DoT++
				out.Count++
			}
		}
		for _, c := range a.ConnectionAttempts {
			if out.Count >= limit {
				out.Capped = true
				return finalize(out)
			}
			if c.RemotePort == 853 {
				out.Hits = append(out.Hits, Hit{
					Kind: KindDoT, DestIP: c.RemoteIP, Port: 853, Protocol: c.Protocol,
					Node: a.Node, Namespace: c.Namespace, Pod: c.Pod, Packets: c.Attempts,
					Label: "DNS-over-TLS connect attempt",
				})
				out.DoT++
				out.Count++
			}
		}
		scanHosts := func(host, kind, ns, pod string, pkts uint64) {
			if out.Count >= limit {
				return
			}
			if label, ok := lookupDoH(catalog, host); ok {
				out.Hits = append(out.Hits, Hit{
					Kind: KindDoH, Host: host, Node: a.Node, Namespace: ns, Pod: pod,
					Packets: pkts, Label: label + " (" + kind + ")",
				})
				out.DoH++
				out.Count++
			}
		}
		for _, t := range a.TLSMetadata {
			scanHosts(t.SNI, "sni", t.Namespace, t.Pod, t.Handshakes)
		}
		for _, h := range a.HTTPMetadata {
			scanHosts(h.Host, "http-host", h.Namespace, h.Pod, h.Requests)
		}
		for _, d := range a.DNSHealth {
			scanHosts(d.Name, "dns", d.Namespace, d.Pod, d.Queries)
		}
	}
	return finalize(out)
}

func finalize(out Result) Result {
	out.Count = len(out.Hits)
	return out
}

func lookupDoH(catalog []struct{ Suffix, Label string }, host string) (string, bool) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return "", false
	}
	bestLabel := ""
	bestLen := -1
	for _, e := range catalog {
		suf := strings.ToLower(e.Suffix)
		if h == suf || strings.HasSuffix(h, "."+suf) {
			if len(suf) > bestLen {
				bestLabel = e.Label
				bestLen = len(suf)
			}
		}
	}
	if bestLen < 0 {
		return "", false
	}
	return bestLabel, true
}
