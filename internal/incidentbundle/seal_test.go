// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package incidentbundle

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef-seal-key")

func TestSealRoundTripAndFailures(t *testing.T) {
	data, _ := build(t, fixture())
	s, err := SealBundle(data, testKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.MAC+s.KeyID, string(testKey)) {
		t.Fatal("key material leaked into the seal")
	}
	sj, _ := json.Marshal(s)
	if err := VerifySeal(data, sj, testKey); err != nil {
		t.Fatalf("good seal rejected: %v", err)
	}
	// Archive form seals the same chain head.
	tgz, err := WriteTarGz(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySeal(tgz, sj, testKey); err != nil {
		t.Fatalf("tgz: %v", err)
	}

	if err := VerifySeal(data, sj, []byte("another-key-another-key")); err == nil || !strings.Contains(err.Error(), "different key") {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := SealBundle(data, []byte("short"), t0); err == nil {
		t.Fatal("short key accepted")
	}
	// Altered MAC with the right key id.
	bad := s
	bad.MAC = strings.Repeat("0", 64)
	bj, _ := json.Marshal(bad)
	if err := VerifySeal(data, bj, testKey); err == nil || !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("forged mac: %v", err)
	}
	// Seal for another bundle.
	in := fixture()
	in.Now = t0.Add(time.Hour)
	other, _ := build(t, in)
	if err := VerifySeal(other, sj, testKey); err == nil || !strings.Contains(err.Error(), "different bundle") {
		t.Fatalf("other bundle: %v", err)
	}
	// Unknown field in the seal is refused.
	var m map[string]any
	_ = json.Unmarshal(sj, &m)
	m["extra"] = 1
	xj, _ := json.Marshal(m)
	if err := VerifySeal(data, xj, testKey); err == nil {
		t.Fatal("unknown seal field accepted")
	}
	// A tampered bundle is never sealed nor accepted, even if the chain is recomputed.
	tampered := bytes.Replace(data, []byte(`"node-a"`), []byte(`"node-z"`), 1)
	if _, err := SealBundle(tampered, testKey, t0); err == nil {
		t.Fatal("tampered bundle sealed")
	}
	if err := VerifySeal(tampered, sj, testKey); err == nil {
		t.Fatal("tampered bundle accepted")
	}
}

func TestReportDeterministicAndHonest(t *testing.T) {
	data, _ := build(t, fixture())
	r1, err := BuildReport(data)
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := BuildReport(data)
	if r1.Markdown() != r2.Markdown() {
		t.Fatal("report not deterministic")
	}
	if r1.Verdict != "breaks" || r1.FirstBreak == nil {
		t.Fatalf("verdict %q first break %+v", r1.Verdict, r1.FirstBreak)
	}
	for _, p := range r1.Precursors {
		if p.Class != "change" || p.SecondsPrev < 0 || p.SecondsPrev > int64(ReportLead/time.Second) {
			t.Fatalf("bad precursor %+v", p)
		}
	}
	for i := 1; i < len(r1.Precursors); i++ {
		if r1.Precursors[i].SecondsPrev < r1.Precursors[i-1].SecondsPrev {
			t.Fatal("precursors must be nearest first")
		}
	}
	md := r1.Markdown()
	for _, want := range []string{"# Incident report draft", "What broke first", "not proof of cause", "How far to trust this", r1.BundleHead} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown lacks %q:\n%s", want, md)
		}
	}
	for _, secret := range secrets {
		if strings.Contains(md, secret) {
			t.Fatalf("report leaked %q", secret)
		}
	}
}

func TestReportQuietWithGapsIsNotReassuring(t *testing.T) {
	in := Inputs{Now: t0, Window: 5 * time.Minute, Version: "0.32.0", Mode: "observe"}
	data, _ := build(t, in)
	r, err := BuildReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != "quiet" {
		t.Fatalf("verdict %q", r.Verdict)
	}
	if !strings.Contains(strings.Join(r.Confidence, "\n"), "not evidence that nothing happened") {
		t.Fatalf("quiet report with blind spots must say so: %v", r.Confidence)
	}
}

func TestReportRefusesBadBundle(t *testing.T) {
	data, _ := build(t, fixture())
	tampered := bytes.Replace(data, []byte(`"node-a"`), []byte(`"node-z"`), 1)
	if _, err := BuildReport(tampered); err == nil {
		t.Fatal("report built from a tampered bundle")
	}
}
