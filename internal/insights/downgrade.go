// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/l7"
	"github.com/zyvorai/netra/internal/models"
)

// ProtocolDowngrades flags a workload/host pair with TLS handshake history
// at baseline capture time now also showing cleartext HTTP to that same
// host — baseline-relative by construction, same gating as Drift, for the
// same reason: no other historical reference exists. Reuses this package's
// existing sourceKey/CaptureBaseline "sni"/"http-host" keyed baseline
// entries directly rather than inventing new scoping.
//
// source == "node" entries (the CanonicalSource fallback when neither pod
// nor cgroup attribution succeeded) are excluded from this correlation
// specifically: node-level merging is exactly the cross-workload
// false-positive case this feature must avoid — a TLS handshake from one
// unattributed process and cleartext HTTP from a completely different one,
// both merged under the same bare "node" source, would look like a
// downgrade that never happened.
//
// L7Degraded/L7DegradedNodes must be checked before reading an empty
// Findings list as "no downgrades observed" — see l7.Degraded's doc
// comment for exactly what that flag does and doesn't mean.
func ProtocolDowngrades(baseline models.BehaviorBaseline, agents []models.AgentStatus) models.ProtocolDowngradeResponse {
	out := models.ProtocolDowngradeResponse{Findings: []models.ProtocolDowngradeFinding{}}
	out.L7Degraded, out.L7DegradedNodes = l7.Degraded(agents)

	if baseline.SchemaVersion == 0 || baseline.CapturedAt.IsZero() {
		return out
	}
	capturedAt := baseline.CapturedAt
	out.BaselineCapturedAt = &capturedAt

	baselineTLSHosts := map[string]map[string]bool{} // source -> lowercased SNI host -> true
	for _, e := range baseline.Entries {
		if e.Kind != "sni" || e.Source == "node" {
			continue
		}
		if baselineTLSHosts[e.Source] == nil {
			baselineTLSHosts[e.Source] = map[string]bool{}
		}
		baselineTLSHosts[e.Source][e.Value] = true
	}
	if len(baselineTLSHosts) == 0 {
		return out
	}

	currentTLSHosts := map[string]map[string]bool{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, t := range a.TLSMetadata {
			if t.Handshakes == 0 {
				continue
			}
			src := sourceKey(t.Namespace, t.Pod, t.WorkloadKind, t.WorkloadName, t.CgroupID)
			if src == "node" {
				continue
			}
			if currentTLSHosts[src] == nil {
				currentTLSHosts[src] = map[string]bool{}
			}
			currentTLSHosts[src][strings.ToLower(t.SNI)] = true
		}
	}

	seen := map[string]bool{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, h := range a.HTTPMetadata {
			if h.Requests == 0 {
				continue
			}
			src := sourceKey(h.Namespace, h.Pod, h.WorkloadKind, h.WorkloadName, h.CgroupID)
			if src == "node" {
				continue
			}
			host := strings.ToLower(h.Host)
			if !baselineTLSHosts[src][host] {
				continue
			}
			key := src + "\x00" + host
			if seen[key] {
				continue
			}
			seen[key] = true

			tlsActive := currentTLSHosts[src][host]
			finding := models.ProtocolDowngradeFinding{Source: src, Host: host, TLSStillActive: tlsActive}
			if tlsActive {
				finding.Severity = "info"
				finding.Message = fmt.Sprintf("%s had TLS handshake history to %s at baseline capture and now also shows cleartext HTTP to the same host, with TLS still concurrently active — likely coexistence (e.g. a secondary client path), not a confirmed downgrade", src, host)
			} else {
				finding.Severity = "warning"
				finding.Message = fmt.Sprintf("%s had TLS handshake history to %s at baseline capture and now shows cleartext HTTP to the same host with no concurrent TLS activity observed", src, host)
			}
			out.Findings = append(out.Findings, finding)
		}
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		if out.Findings[i].Severity != out.Findings[j].Severity {
			return out.Findings[i].Severity == "warning"
		}
		if out.Findings[i].Source != out.Findings[j].Source {
			return out.Findings[i].Source < out.Findings[j].Source
		}
		return out.Findings[i].Host < out.Findings[j].Host
	})
	return out
}
