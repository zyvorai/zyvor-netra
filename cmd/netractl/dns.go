// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "fmt"

// Classify only the native, matched UDP response event. A DNS query or a
// generic event carrying a name must never become evidence of a DNS failure.
func dnsResponseFinding(e explainEvent) (kind, evidence, next string) {
	if e.Type != "dns-response" || e.Action != "observed" || e.Protocol != "UDP" ||
		e.Hook != "cgroup" || e.Direction != "ingress" || e.SourcePort != 53 || e.DNSQuery == "" || e.DNSRcode > 15 {
		return
	}
	name := fmt.Sprintf("RCODE_%d", e.DNSRcode)
	kind = "dns-response-error"
	switch e.DNSRcode {
	case 0:
		name, kind = "NOERROR", "dns-response"
		next = "The base DNS header reports no error. This does not prove an answer record exists, DNSSEC validation, or application connectivity."
	case 1:
		name = "FORMERR"
		next = "The resolver reported a malformed request. Check client DNS encoding and resolver compatibility."
	case 2:
		name = "SERVFAIL"
		next = "Check resolver and upstream logs, DNSSEC validation, and authoritative-server reachability; SERVFAIL alone does not identify which failed."
	case 3:
		name = "NXDOMAIN"
		next = "The resolver reported that the queried name does not exist. Check spelling, search domains, namespace qualification, and authoritative records."
	case 4:
		name = "NOTIMP"
		next = "Check whether the resolver supports the requested DNS operation."
	case 5:
		name = "REFUSED"
		next = "Check resolver access controls and recursion policy for the requesting workload; refusal is not evidence of packet loss."
	default:
		next = "Inspect the numeric base-header response code and resolver logs; no specific cause is inferred."
	}
	evidence = fmt.Sprintf("name=%q resolver=%q rcode=%s(%d) latency-us=%d hook=cgroup observedAt=%q", e.DNSQuery, e.SourceIP, name, e.DNSRcode, e.LatencyUS, e.ObservedAt.Format("2006-01-02T15:04:05.999999999Z07:00"))
	return
}
