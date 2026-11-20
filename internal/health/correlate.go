// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package health

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

// workloadKey strips a subject() string down to its workload/node portion,
// dropping any "→ remote:port" suffix — subject() bakes the specific remote
// endpoint into TCP/DNS anomaly subjects, which would otherwise stop e.g. a
// DNS-failure anomaly (subject "ns/pod → db.internal:53") from correlating
// with a TCP-retransmit anomaly on the same workload but a different remote
// (subject "ns/pod → 10.0.0.8:443") even though both describe one workload.
func workloadKey(subject string) string {
	if before, _, ok := strings.Cut(subject, " → "); ok {
		return before
	}
	return subject
}

// correlateAnomalies groups the anomalies already found by anomalies() by
// their shared workload/node key and, when a key has two or more distinct
// anomaly Kinds in the same build cycle, appends one composite finding
// naming them. This supplements the individual findings — it never removes
// or replaces them, since those remain the exact evidence netractl explain
// depends on.
func correlateAnomalies(in []models.NetworkHealthAnomaly) []models.NetworkHealthAnomaly {
	byKey := map[string][]models.NetworkHealthAnomaly{}
	order := []string{}
	for _, a := range in {
		k := workloadKey(a.Subject)
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], a)
	}

	out := append([]models.NetworkHealthAnomaly(nil), in...)
	for _, key := range order {
		if key == "" {
			continue
		}
		group := byKey[key]
		kinds := map[string]bool{}
		for _, a := range group {
			kinds[a.Kind] = true
		}
		if len(kinds) < 2 {
			continue
		}
		related := make([]string, 0, len(kinds))
		for k := range kinds {
			related = append(related, k)
		}
		sort.Strings(related)
		severity := "info"
		severityRank := map[string]int{"info": 1, "warning": 2, "critical": 3}
		for _, a := range group {
			if severityRank[a.Severity] > severityRank[severity] {
				severity = a.Severity
			}
		}
		out = append(out, models.NetworkHealthAnomaly{
			Severity:     severity,
			Kind:         "correlated-degradation",
			Subject:      key,
			Message:      fmt.Sprintf("%d independent anomaly kinds observed for the same subject in this build: %v", len(related), related),
			Value:        float64(len(related)),
			RelatedKinds: related,
		})
	}
	return out
}
