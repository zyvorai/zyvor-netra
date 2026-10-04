// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"context"
	"strings"
	"testing"
)

func metricSnap() Snapshot {
	return Snapshot{AgentsTotal: 2, HealthScore: 95, Metrics: []Finding{
		{Severity: "critical", Kind: "metric-alert", Subject: "disk_space_usage", Message: "disk_space_usage critical on n1 disk_space._/used = 97 %"},
		{Severity: "info", Kind: "metric-anomaly", Subject: "n1 net.eth0/received", Message: "n1 net.eth0/received anomalous 40% of the last 15m"},
	}}
}

func TestMetricFindingsDriveBriefAndIntent(t *testing.T) {
	b := BuildBrief(metricSnap())
	if b.Severity != "critical" {
		t.Fatalf("severity %s", b.Severity)
	}
	if Classify("which metrics are anomalous?") != IntentMetrics || Classify("why are packets dropped") != IntentDrops {
		t.Fatal("classify")
	}
	a := Answer(context.Background(), metricSnap(), "any metric alerts?", nil, "")
	if a.Headline != "Metric alerts and anomalies" || !strings.Contains(a.Summary, "1 metric alert(s) raised, 1 anomalous metric(s)") || !strings.Contains(a.Summary, "net.eth0/received") {
		t.Fatalf("answer %+v", a)
	}
	if !strings.Contains(strings.Join(a.NextSteps, " "), "metrics evidence") {
		t.Fatalf("next steps %v", a.NextSteps)
	}
	quiet := Answer(context.Background(), Snapshot{AgentsTotal: 1}, "metric anomalies?", nil, "")
	if !strings.HasPrefix(quiet.Summary, "No metric alerts are raised") {
		t.Fatalf("quiet %s", quiet.Summary)
	}
	found := false
	for _, s := range Suggestions(metricSnap()) {
		found = found || strings.Contains(s, "metrics are alerting")
	}
	if !found {
		t.Fatal("no metrics suggestion")
	}
}

func TestFingerprintTracksMetricAlertsNotAnomalies(t *testing.T) {
	base := Snapshot{AgentsTotal: 1, HealthScore: 90}
	withAnom := base
	withAnom.Metrics = []Finding{{Kind: "metric-anomaly", Subject: "x"}}
	if Fingerprint(base, "info") != Fingerprint(withAnom, "info") {
		t.Fatal("anomaly ranking must not churn the fingerprint")
	}
	withAlert := base
	withAlert.Metrics = []Finding{{Kind: "metric-alert", Subject: "ram_in_use"}}
	if Fingerprint(base, "info") == Fingerprint(withAlert, "info") {
		t.Fatal("a raised metric alert must change the fingerprint")
	}
	why := explainFingerprintChange(fingerprintComponentsOf(base, "info"), fingerprintComponentsOf(withAlert, "info"))
	if len(why) != 1 || why[0] != "metric alert raised: ram_in_use" {
		t.Fatalf("why %v", why)
	}
}
