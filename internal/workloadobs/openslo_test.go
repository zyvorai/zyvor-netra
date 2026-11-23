// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package workloadobs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodSLO = `apiVersion: openslo/v1
kind: SLO
metadata:
  name: checkout-availability
  annotations:
    netra.zyvor.dev/sli: http_5xx
    netra.zyvor.dev/namespace: shop
    netra.zyvor.dev/workload: Deployment/checkout
spec:
  budgetingMethod: Occurrences
  timeWindow:
    - duration: 30d
      isRolling: true
  objectives:
    - target: 0.999
---
apiVersion: openslo/v1
kind: SLO
metadata:
  name: dns-ok
  annotations: {netra.zyvor.dev/sli: dns_failure}
spec:
  timeWindow: [{duration: 7d}]
  objectives: [{targetPercent: 99.5}]
`

func TestParseOpenSLOGood(t *testing.T) {
	defs, err := ParseOpenSLO([]byte(goodSLO))
	if err != nil || len(defs) != 2 {
		t.Fatalf("%v %v", defs, err)
	}
	a := defs[0]
	if a.Name != "checkout-availability" || a.SLI != SLIHTTP5xx || a.TargetPct != 99.9 || a.Window != 30*24*time.Hour || a.Namespace != "shop" || a.Workload != "Deployment/checkout" {
		t.Fatalf("%+v", a)
	}
	if defs[1].TargetPct != 99.5 || defs[1].Window != 7*24*time.Hour {
		t.Fatalf("%+v", defs[1])
	}
	if d, err := ParseOpenSLO(nil); err != nil || len(d) != 0 {
		t.Fatalf("empty: %v %v", d, err)
	}
}

func TestParseOpenSLORejects(t *testing.T) {
	mutate := func(old, new string) string { return strings.Replace(goodSLO, old, new, 1) }
	cases := map[string]string{
		"wrong version":     mutate("openslo/v1", "openslo/v2alpha"),
		"wrong kind":        mutate("kind: SLO", "kind: SLI"),
		"no sli annotation": mutate("netra.zyvor.dev/sli: http_5xx", "x: y"),
		"unknown sli":       mutate("http_5xx", "latency_p99"),
		"timeslices":        mutate("Occurrences", "Timeslices"),
		"calendar window":   mutate("isRolling: true", "isRolling: false"),
		"bad window":        mutate("30d", "5m"),
		"no window":         mutate("duration: 30d", "duration: \"\""),
		"target 1.0":        mutate("target: 0.999", "target: 1.0"),
		"target 0.2":        mutate("target: 0.999", "target: 0.2"),
		"negative":          mutate("target: 0.999", "target: -1"),
		"both targets":      mutate("target: 0.999", "target: 0.999\n      targetPercent: 99.9"),
		"two objectives":    mutate("- target: 0.999", "- target: 0.999\n    - target: 0.99"),
		"bad name":          mutate("checkout-availability", "../etc/passwd"),
		"threshold metric":  mutate("spec:\n  budgetingMethod", "spec:\n  indicator: {spec: {thresholdMetric: {}}}\n  budgetingMethod"),
		"duplicate":         goodSLO + "---\n" + strings.Split(goodSLO, "---")[0],
		"not yaml":          "kind: [unclosed",
		"too big":           strings.Repeat("#", maxOpenSLOBytes+1),
	}
	for name, doc := range cases {
		if _, err := ParseOpenSLO([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestConfigFromEnvMergesSLOFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "slo.yaml")
	if err := os.WriteFile(path, []byte(goodSLO), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"NETRA_SLO_FILE": path,
		"NETRA_SLO_DEFINITIONS": `[{"name":"extra","sli":"dns_failure","targetPct":99.9}]`}
	cfg, err := ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil || len(cfg.SLOs) != 3 || !cfg.Enabled() {
		t.Fatalf("%v %+v", err, cfg.SLOs)
	}
	env["NETRA_SLO_DEFINITIONS"] = `[{"name":"dns-ok","sli":"dns_failure","targetPct":99.9}]`
	if _, err := ConfigFromEnv(func(k string) string { return env[k] }); err == nil {
		t.Fatal("duplicate across env and file accepted")
	}
	env["NETRA_SLO_FILE"] = filepath.Join(dir, "missing.yaml")
	if _, err := ConfigFromEnv(func(k string) string { return env[k] }); err == nil {
		t.Fatal("missing file accepted")
	}
}
