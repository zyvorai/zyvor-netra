// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"fmt"
	"strings"
)

type explainNamedCount struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

func (o explainOptions) includesRateDrops() bool {
	return o.Namespace == "" && o.Pod == "" && o.PID == 0 && o.Container == "" &&
		o.Docker == "" && o.DNS == ""
}

func bpfMapsMissingFinding(missingMaps []string) (kind, evidence, next string) {
	if len(missingMaps) == 0 {
		return
	}
	kind = "bpf-maps-missing"
	evidence = fmt.Sprintf("missing-maps=%q", strings.Join(missingMaps, ","))
	next = "Rebuild and roll the agent image so allow/rate/icmp maps exist. Until then those controls fail open."
	return
}

func rateDropFinding(d explainNamedCount) (kind, evidence, next string) {
	if d.Count == 0 {
		return
	}
	kind = "rate-drop"
	evidence = fmt.Sprintf("destination=%q dropped=%d", d.Name, d.Count)
	next = "Check whether this destination's PPS ceiling is set too low for legitimate traffic; rate-drop counters are cumulative since the map was created and do not identify which flows were dropped or when."
	return
}
