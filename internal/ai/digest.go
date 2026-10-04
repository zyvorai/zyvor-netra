// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Digest is a pager/Slack-ready card plus a fingerprint so two operators
// can tell whether they are looking at the same incident cluster.
type Digest struct {
	Headline    string    `json:"headline"`
	Severity    string    `json:"severity"`
	Fingerprint string    `json:"fingerprint"`
	Changed     bool      `json:"changed"`
	Previous    string    `json:"previousFingerprint,omitempty"`
	Card        string    `json:"card"`
	Suggestions []string  `json:"suggestions"`
	GeneratedAt time.Time `json:"generatedAt"`
	Brief       Brief     `json:"brief"`
	// WhyChanged is a deterministic, always-complete list of what moved
	// since the previous digest — set only when Changed is true. The
	// fingerprint itself is a one-way SHA-256 hash and cannot be
	// decomposed (see internal/timeline's digestTransitions doc comment);
	// this instead keeps the plain pre-hash components alongside it, so
	// two different fingerprints are guaranteed to explain at least one
	// difference here.
	WhyChanged []string `json:"whyChanged,omitempty"`
	// WhyChangedProse is an optional one-sentence LLM rewrite of
	// WhyChanged (see NarrateWhyChanged) — empty unless a provider is
	// configured and narration succeeded.
	WhyChangedProse string `json:"whyChangedProse,omitempty"`
}

// fingerprintComponents is the plain, pre-hash signal set Fingerprint
// hashes, kept alongside the hash (not derived from it — the hash is
// one-way by design) so a later digest can say exactly what changed.
// Every field here must stay in lockstep with Fingerprint's own parts
// construction: this is the complete input to the hash, so two snapshots
// producing different fingerprints are guaranteed to differ in at least
// one of these fields.
type fingerprintComponents struct {
	Mode             string
	Severity         string
	HealthBucket     int
	AgentsStale      int
	Exposure         int
	Drift            int
	AnomalyKinds     []string
	DriftKinds       []string
	ExposureSeverity []string
	MetricAlerts     []string
}

func fingerprintComponentsOf(snap Snapshot, sev string) fingerprintComponents {
	c := fingerprintComponents{
		Mode:         strings.ToLower(orDefault(snap.Mode, "observe")),
		Severity:     strings.ToLower(orDefault(sev, "info")),
		HealthBucket: snap.HealthScore / 10,
		AgentsStale:  snap.AgentsStale,
		Exposure:     snap.HighExposure,
		Drift:        minInt(snap.DriftFindings, 9),
	}
	for _, f := range snap.Anomalies {
		c.AnomalyKinds = append(c.AnomalyKinds, strings.ToLower(f.Kind))
	}
	for _, f := range snap.Drift {
		c.DriftKinds = append(c.DriftKinds, strings.ToLower(f.Kind))
	}
	for _, f := range snap.Exposure {
		c.ExposureSeverity = append(c.ExposureSeverity, strings.ToLower(f.Severity))
	}
	c.MetricAlerts = metricAlertRules(snap)
	return c
}

// metricAlertRules lists raised metric alert rules for the fingerprint.
// Metric anomalies are left out: their ranking moves every scrape.
func metricAlertRules(snap Snapshot) []string {
	var out []string
	for _, f := range snap.Metrics {
		if f.Kind == "metric-alert" {
			out = append(out, strings.ToLower(f.Subject))
		}
	}
	return out
}

var (
	watchMu        sync.Mutex
	lastPrint      string
	lastAt         time.Time
	lastComponents fingerprintComponents
	haveComponents bool
)

// RecordFingerprint remembers the last digest fingerprint in process
// memory so the next digest can set Changed. Not persisted across
// controller restarts — that is intentional (fail-open, no extra store).
func RecordFingerprint(fp string) {
	if fp == "" {
		return
	}
	watchMu.Lock()
	lastPrint = fp
	lastAt = time.Now().UTC()
	watchMu.Unlock()
}

func lastFingerprint() (string, time.Time) {
	watchMu.Lock()
	defer watchMu.Unlock()
	return lastPrint, lastAt
}

// recordFingerprintComponents remembers the plain components behind the
// most recent fingerprint, alongside RecordFingerprint's hash — the two
// are always set together from BuildDigest, so they share process
// lifetime and reset together on restart.
func recordFingerprintComponents(c fingerprintComponents) {
	watchMu.Lock()
	lastComponents = c
	haveComponents = true
	watchMu.Unlock()
}

func lastFingerprintComponents() (fingerprintComponents, bool) {
	watchMu.Lock()
	defer watchMu.Unlock()
	return lastComponents, haveComponents
}

// Fingerprint is a short stable id over the *shape* of the snapshot:
// mode, health bucket, stale agents, and finding kinds — not counters
// that chatter every scrape. Two briefs with the same fingerprint are
// the same incident cluster.
func Fingerprint(snap Snapshot, sev string) string {
	parts := []string{
		strings.ToLower(orDefault(snap.Mode, "observe")),
		strings.ToLower(orDefault(sev, "info")),
		fmt.Sprintf("stale=%d", snap.AgentsStale),
		fmt.Sprintf("health=%d", snap.HealthScore/10),
		fmt.Sprintf("expo=%d", snap.HighExposure),
		fmt.Sprintf("drift=%d", minInt(snap.DriftFindings, 9)),
	}
	for _, f := range snap.Anomalies {
		parts = append(parts, "a:"+strings.ToLower(f.Kind))
	}
	for _, f := range snap.Drift {
		parts = append(parts, "d:"+strings.ToLower(f.Kind))
	}
	for _, f := range snap.Exposure {
		parts = append(parts, "e:"+strings.ToLower(f.Severity))
	}
	for _, r := range metricAlertRules(snap) {
		parts = append(parts, "m:"+r)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:12]
}

// Suggestions returns live follow-up questions derived from the snapshot
// rather than a static chip list.
func Suggestions(snap Snapshot) []string {
	out := make([]string, 0, 6)
	if snap.AgentsTotal == 0 {
		return []string{"Why are no node agents reporting?", "How do I run netra-doctor?"}
	}
	if snap.AgentsStale > 0 {
		out = append(out, "Which agents are stale and why does that matter?")
	}
	if snap.HealthScore < 85 || hasKind(snap.Anomalies, "dns") {
		out = append(out, "Why does network health look off?")
	}
	if snap.Blocked > 0 || len(snap.BlockReasons) > 0 {
		out = append(out, "Why are packets being dropped?")
	}
	if hasKind(snap.Metrics, "metric-") {
		out = append(out, "Which metrics are alerting or anomalous, and what explains them?")
	}
	if snap.HighExposure > 0 || snap.ExternalEdges > 0 {
		out = append(out, "What is newly exposed outside the cluster?")
	}
	if snap.Recommendations > 0 {
		out = append(out, "Which policy drafts need review?")
	}
	if strings.EqualFold(snap.Mode, "enforce") {
		out = append(out, "When does the enforce lease expire?")
	}
	if len(out) == 0 {
		out = append(out, "What looks unhealthy?", "Are we in enforce mode?")
	}
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

// BuildDigest turns a brief into an on-call card.
func BuildDigest(brief Brief) Digest {
	fp := Fingerprint(brief.Snapshot, brief.Severity)
	prev, _ := lastFingerprint()
	changed := prev != "" && prev != fp
	curComponents := fingerprintComponentsOf(brief.Snapshot, brief.Severity)

	var why []string
	if changed {
		if prevComponents, ok := lastFingerprintComponents(); ok {
			why = explainFingerprintChange(prevComponents, curComponents)
		} else {
			why = []string{"previous incident's signal breakdown wasn't recorded (controller restarted since); showing the new snapshot only"}
		}
	}

	card := formatCard(brief, fp, prev, why)
	d := Digest{
		Headline:    brief.Headline,
		Severity:    brief.Severity,
		Fingerprint: fp,
		Changed:     changed,
		Previous:    prev,
		Card:        card,
		Suggestions: Suggestions(brief.Snapshot),
		GeneratedAt: brief.GeneratedAt,
		Brief:       brief,
		WhyChanged:  why,
	}
	RecordFingerprint(fp)
	recordFingerprintComponents(curComponents)
	return d
}

// explainFingerprintChange compares prev and cur component snapshots and
// returns one bullet per dimension that moved. fingerprintComponents is
// the complete input Fingerprint hashes, so if two fingerprints differ,
// this is guaranteed to return at least one bullet — never silently
// empty for an actual change.
func explainFingerprintChange(prev, cur fingerprintComponents) []string {
	var out []string
	if prev.Mode != cur.Mode {
		out = append(out, fmt.Sprintf("fast-path mode changed from %s to %s", prev.Mode, cur.Mode))
	}
	if prev.Severity != cur.Severity {
		out = append(out, fmt.Sprintf("severity moved from %s to %s", prev.Severity, cur.Severity))
	}
	if prev.HealthBucket != cur.HealthBucket {
		dir := "dropped"
		if cur.HealthBucket > prev.HealthBucket {
			dir = "improved"
		}
		out = append(out, fmt.Sprintf("health score band %s (was %d0s, now %d0s)", dir, prev.HealthBucket, cur.HealthBucket))
	}
	if prev.AgentsStale != cur.AgentsStale {
		out = append(out, fmt.Sprintf("stale agent count changed from %d to %d", prev.AgentsStale, cur.AgentsStale))
	}
	if prev.Exposure != cur.Exposure {
		out = append(out, fmt.Sprintf("high-exposure item count changed from %d to %d", prev.Exposure, cur.Exposure))
	}
	if prev.Drift != cur.Drift {
		out = append(out, fmt.Sprintf("drift finding count changed from %d to %d", prev.Drift, cur.Drift))
	}
	for _, k := range setAdded(prev.AnomalyKinds, cur.AnomalyKinds) {
		out = append(out, "new anomaly kind: "+k)
	}
	for _, k := range setAdded(cur.AnomalyKinds, prev.AnomalyKinds) {
		out = append(out, "anomaly kind resolved: "+k)
	}
	for _, k := range setAdded(prev.DriftKinds, cur.DriftKinds) {
		out = append(out, "new drift kind: "+k)
	}
	for _, k := range setAdded(cur.DriftKinds, prev.DriftKinds) {
		out = append(out, "drift kind resolved: "+k)
	}
	for _, k := range setAdded(prev.ExposureSeverity, cur.ExposureSeverity) {
		out = append(out, "new exposure severity present: "+k)
	}
	for _, k := range setAdded(cur.ExposureSeverity, prev.ExposureSeverity) {
		out = append(out, "exposure severity resolved: "+k)
	}
	for _, k := range setAdded(prev.MetricAlerts, cur.MetricAlerts) {
		out = append(out, "metric alert raised: "+k)
	}
	for _, k := range setAdded(cur.MetricAlerts, prev.MetricAlerts) {
		out = append(out, "metric alert cleared: "+k)
	}
	return out
}

// setAdded returns the elements of to not present in from, deduplicated
// and sorted for stable output — used both directions by
// explainFingerprintChange to describe additions and removals.
func setAdded(from, to []string) []string {
	have := make(map[string]bool, len(from))
	for _, v := range from {
		have[v] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, v := range to {
		if have[v] || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// NarrateWhyChanged asks p to rewrite d.WhyChanged into one short
// sentence, same "deterministic step, optional LLM prose on top" split as
// timeline.Narrate. d is returned unchanged (WhyChangedProse stays empty)
// when p is nil/disabled, the digest didn't change, or there is nothing
// to explain — the deterministic bullets in WhyChanged are always a
// complete answer on their own.
func NarrateWhyChanged(ctx context.Context, d Digest, p *Provider) Digest {
	if p == nil || !p.Enabled() || !d.Changed || len(d.WhyChanged) == 0 {
		return d
	}
	sys := strings.Join([]string{
		"You are Netra's read-only network observability assistant.",
		"Rewrite the following bullet list of what changed between two incident digests into one short sentence.",
		"Use only the facts given; never invent a cause, counter, or workload not stated in the bullets.",
		"Keep the answer under 40 words.",
	}, " ")
	var b strings.Builder
	for _, w := range d.WhyChanged {
		b.WriteString("- " + w + "\n")
	}
	rewritten, err := p.RewriteText(ctx, sys, b.String())
	if err != nil || strings.TrimSpace(rewritten) == "" {
		return d
	}
	d.WhyChangedProse = rewritten
	return d
}

func formatCard(b Brief, fp, prev string, why []string) string {
	var s strings.Builder
	fmt.Fprintf(&s, "NETRA DIGEST · %s · health %d/100\n", strings.ToUpper(b.Severity), b.Snapshot.HealthScore)
	fmt.Fprintf(&s, "Fingerprint %s", fp)
	if prev != "" && prev != fp {
		fmt.Fprintf(&s, " (was %s)", prev)
	}
	s.WriteByte('\n')
	if len(why) > 0 {
		s.WriteString("Why:\n")
		for _, w := range why {
			fmt.Fprintf(&s, "- %s\n", w)
		}
	}
	fmt.Fprintf(&s, "%s\n\n", b.Headline)
	fmt.Fprintf(&s, "%s\n", b.Summary)
	if len(b.Findings) > 0 {
		s.WriteString("\nFindings:\n")
		for i, f := range b.Findings {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&s, "- [%s] %s\n", orDefault(f.Severity, "info"), f.Message)
		}
	}
	if len(b.NextSteps) > 0 {
		s.WriteString("\nNext:\n")
		for i, n := range b.NextSteps {
			if i >= 4 {
				break
			}
			fmt.Fprintf(&s, "- %s\n", n)
		}
	}
	s.WriteString("\nRead-only. Do not treat this card as an apply instruction.\n")
	return s.String()
}

func hasKind(findings []Finding, needle string) bool {
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Kind+" "+f.Message), needle) {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
