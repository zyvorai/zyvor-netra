// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package timeline turns the controller's existing audit log and its
// bounded cluster-health-sample history (internal/store/history.go) into a
// single chronological, human-readable incident timeline. ExplainAuditEvent
// is exported so internal/incident's cross-signal correlator (a later item
// in the same plan) can reuse the same audit-event phrasing instead of a
// second, divergent implementation.
package timeline

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/ai"
	"github.com/zyvorai/netra/internal/models"
)

// Build merges audit events and cluster-health-sample transitions into one
// chronological timeline, filtering both to At >= since (a zero since keeps
// everything given). This is the pure, deterministic step — see Narrate for
// the optional LLM prose rewrite layered on top, same split as
// internal/ai.BuildBrief (pure) vs internal/ai.Answer (optional rewrite).
func Build(audit []models.AuditEvent, samples []models.ClusterHealthSample, since time.Time) models.Timeline {
	var entries []models.TimelineEntry
	for _, ev := range audit {
		if !since.IsZero() && ev.At.Before(since) {
			continue
		}
		entries = append(entries, models.TimelineEntry{At: ev.At, Kind: "audit", Text: ExplainAuditEvent(ev)})
	}
	for _, e := range digestTransitions(samples) {
		if !since.IsZero() && e.At.Before(since) {
			continue
		}
		entries = append(entries, e)
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].At.Before(entries[j].At) })

	out := models.Timeline{GeneratedAt: time.Now().UTC(), Entries: entries, Engine: "heuristic"}
	if !since.IsZero() {
		s := since.UTC()
		out.Since = &s
	}
	return out
}

// Narrate asks p to rewrite tl's bullet-point entries into a short flowing
// paragraph. tl is returned unchanged (Engine stays "heuristic", Prose
// stays empty) when p is nil/disabled, there are no entries, or the
// provider call fails — the deterministic timeline is always a complete
// answer on its own.
func Narrate(ctx context.Context, tl models.Timeline, p *ai.Provider) models.Timeline {
	if p == nil || !p.Enabled() || len(tl.Entries) == 0 {
		return tl
	}
	sys := strings.Join([]string{
		"You are Netra's read-only network observability assistant.",
		"Rewrite the following chronological bullet-point incident timeline into a short flowing narrative paragraph.",
		"Use only the facts given; never invent counters, IPs, workloads, timestamps, or root causes not stated.",
		"Never recommend running enforce mode without an explicit human lease renewal.",
		"Keep the answer under 200 words.",
	}, " ")
	var b strings.Builder
	for _, e := range tl.Entries {
		fmt.Fprintf(&b, "- %s: %s\n", e.At.Format(time.RFC3339), e.Text)
	}
	rewritten, err := p.RewriteText(ctx, sys, b.String())
	if err != nil || strings.TrimSpace(rewritten) == "" {
		return tl
	}
	tl.Prose = rewritten
	tl.Engine = "llm"
	return tl
}

// digestTransitions derives an entry only where consecutive fingerprinted
// samples' Fingerprint differs. Samples with no Fingerprint (ebpfHealth's
// producer doesn't set one — see internal/store/history.go's producer
// list) are skipped entirely for this derivation rather than compared, so
// an unfingerprinted sample landing between two fingerprinted ones never
// manufactures a spurious transition. Fingerprint is a one-way SHA-256 hash
// by design (internal/ai/digest.go) and cannot be decomposed to say what
// specifically changed, so the wording here comes from the adjacent plain
// fields (Severity/HealthScore/Mode) only — never from the hash itself.
func digestTransitions(samples []models.ClusterHealthSample) []models.TimelineEntry {
	var withFP []models.ClusterHealthSample
	for _, s := range samples {
		if s.Fingerprint != "" {
			withFP = append(withFP, s)
		}
	}
	var out []models.TimelineEntry
	for i := 1; i < len(withFP); i++ {
		if withFP[i].Fingerprint == withFP[i-1].Fingerprint {
			continue
		}
		out = append(out, models.TimelineEntry{
			At:       withFP[i].At,
			Kind:     "digest-transition",
			Severity: withFP[i].Severity,
			Text: fmt.Sprintf("cluster health signature changed (%s → %s), health score %d/100, mode %s",
				orDefault(withFP[i-1].Severity, "info"), orDefault(withFP[i].Severity, "info"), withFP[i].HealthScore, orDefault(withFP[i].Mode, "observe")),
		})
	}
	return out
}

// specificTemplates covers audit actions whose meaning the generic
// noun+verb fallback below doesn't capture well: system-driven
// lease/restart events, and mode/scope/shield toggles where Target holds
// the new value rather than an identifier of what changed.
var specificTemplates = map[string]func(models.AuditEvent) string{
	"ebpf.mode": func(ev models.AuditEvent) string {
		return fmt.Sprintf("%s switched fast-path mode to %s", actorOf(ev), ev.Target)
	},
	"ebpf.scope.set": func(ev models.AuditEvent) string {
		return fmt.Sprintf("%s updated the fast-path scope (mode %s, %s scope(s))", actorOf(ev), ev.Target, detailOr(ev, "scopes", "?"))
	},
	"ebpf.shield.set": func(ev models.AuditEvent) string {
		return fmt.Sprintf("%s updated the DDoS shield (mode %s)", actorOf(ev), ev.Target)
	},
	"ebpf.lease.expired": func(models.AuditEvent) string {
		return "the enforce-mode lease expired; fast-path mode automatically reverted to observe"
	},
	"ebpf.restart.fail-open": func(models.AuditEvent) string {
		return "the controller restarted while fast-path enforcement was active and failed open to observe, by design"
	},
	"ebpf.netpol.default-deny.expired": func(ev models.AuditEvent) string {
		return fmt.Sprintf("the NetPol v2 default-deny lease for %s expired and automatically reverted", ev.Target)
	},
	"ebpf.netpol.default-deny.restart-fail-open": func(models.AuditEvent) string {
		return "the controller restarted while NetPol v2 default-deny was active and failed open, by design"
	},
	"policy.apply": func(ev models.AuditEvent) string {
		return fmt.Sprintf("%s applied a CiliumNetworkPolicy change to %s", actorOf(ev), ev.Target)
	},
	"policy.delete": func(ev models.AuditEvent) string {
		return fmt.Sprintf("%s deleted the CiliumNetworkPolicy for %s", actorOf(ev), ev.Target)
	},
	"policy.rollback": func(ev models.AuditEvent) string {
		return fmt.Sprintf("%s rolled back %s to revision %s", actorOf(ev), ev.Target, detailOr(ev, "revision", "?"))
	},
	"policy.history.import": func(ev models.AuditEvent) string {
		return fmt.Sprintf("%s imported %s policy revision(s)", actorOf(ev), detailOr(ev, "count", "some"))
	},
	"insights.baseline.capture": func(ev models.AuditEvent) string {
		return fmt.Sprintf("%s captured a new behavior baseline (%s entries)", actorOf(ev), detailOr(ev, "entries", "?"))
	},
	"insights.baseline.clear": func(ev models.AuditEvent) string {
		return fmt.Sprintf("%s cleared the behavior baseline", actorOf(ev))
	},
	"insights.rate-baseline.capture": func(ev models.AuditEvent) string {
		return fmt.Sprintf("%s captured a new traffic-rate baseline (%s entries)", actorOf(ev), detailOr(ev, "entries", "?"))
	},
	"insights.rate-baseline.clear": func(ev models.AuditEvent) string {
		return fmt.Sprintf("%s cleared the traffic-rate baseline", actorOf(ev))
	},
}

// nounTable and verbTable drive the fallback for every other audit action
// (mostly the ~40 "ebpf.<kind>.add"/".delete"/".patch" fast-path-rule
// actions): a noun by longest-matching Action prefix, a verb by Action
// suffix. This is deliberately the highest-maintenance part of this
// feature — new call sites elsewhere in the codebase can add an Action this
// table doesn't recognize, in which case genericExplain returns false and
// ExplainAuditEvent falls through to a plain, still-truthful "<actor>
// performed <action> on <target>" rather than a wrong-sounding guess.
var nounTable = []struct{ prefix, noun string }{
	{"ebpf.allow-cidr", "CIDR allow rule"},
	{"ebpf.allow-port", "port allow rule"},
	{"ebpf.allow-process", "process allow rule"},
	{"ebpf.allow-uid", "UID allow rule"},
	{"ebpf.allow6", "IPv6 allow rule"},
	{"ebpf.allow", "allow rule"},
	{"ebpf.deny-capability", "capability-gated deny rule"},
	{"ebpf.deny-ingress6", "IPv6 ingress deny rule"},
	{"ebpf.deny-ingress", "ingress deny rule"},
	{"ebpf.deny6", "IPv6 deny rule"},
	{"ebpf.deny", "deny rule"},
	{"ebpf.cidr", "CIDR deny rule"},
	{"ebpf.port", "port deny rule"},
	{"ebpf.process", "process deny rule"},
	{"ebpf.uid", "UID deny rule"},
	{"ebpf.sni", "SNI deny rule"},
	{"ebpf.dns", "DNS deny rule"},
	{"ebpf.syndrop", "SYN-drop rule"},
	{"ebpf.connratelimit", "connection-rate-limit rule"},
	{"ebpf.netpol.default-deny", "NetPol v2 default-deny"},
	{"ebpf.netpol.rule", "NetPol v2 rule"},
	{"ebpf.rule.patch", "fast-path rule"},
}

var verbTable = []struct{ suffix, verb string }{
	{".add", "added"},
	{".delete", "removed"},
	{".patch", "edited"},
}

// ExplainAuditEvent turns one AuditEvent into a single human-readable
// sentence: an exact template when one exists, a generic noun+verb
// fallback for anything matching the fast-path-rule naming convention, and
// a plain last-resort sentence otherwise. Never panics, never returns an
// empty string.
func ExplainAuditEvent(ev models.AuditEvent) string {
	if fn, ok := specificTemplates[ev.Action]; ok {
		return fn(ev)
	}
	if s, ok := genericExplain(ev); ok {
		return s
	}
	return fmt.Sprintf("%s performed %s on %s", actorOf(ev), ev.Action, orDefault(ev.Target, "an unspecified target"))
}

func genericExplain(ev models.AuditEvent) (string, bool) {
	noun := ""
	for _, n := range nounTable {
		if strings.HasPrefix(ev.Action, n.prefix) {
			noun = n.noun
			break
		}
	}
	if noun == "" {
		return "", false
	}
	verb := "changed"
	for _, v := range verbTable {
		if strings.HasSuffix(ev.Action, v.suffix) {
			verb = v.verb
			break
		}
	}
	article := "a"
	if len(noun) > 0 && isVowel(noun[0]) {
		article = "an"
	}
	return fmt.Sprintf("%s %s %s %s for %s", actorOf(ev), verb, article, noun, orDefault(ev.Target, "an unspecified target")), true
}

func isVowel(b byte) bool {
	switch b {
	case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U':
		return true
	default:
		return false
	}
}

func actorOf(ev models.AuditEvent) string {
	return orDefault(ev.Actor, "someone")
}

func detailOr(ev models.AuditEvent, key, fallback string) string {
	if ev.Details == nil {
		return fallback
	}
	if v, ok := ev.Details[key]; ok {
		return fmt.Sprint(v)
	}
	return fallback
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
