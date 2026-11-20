// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package kube

import (
	"strings"
	"testing"
)

func TestParseWarningEvents(t *testing.T) {
	raw := []byte(`{"items":[
		{"type":"Warning","reason":"Unhealthy","message":"Readiness probe failed: HTTP","count":2,
		 "involvedObject":{"kind":"Pod","name":"api","namespace":"app"},
		 "lastTimestamp":"2026-09-18T12:00:00Z"},
		{"type":"Normal","reason":"Pulled","message":"image","involvedObject":{"kind":"Pod","name":"skip","namespace":"app"}},
		{"type":"Warning","reason":"BackOff","message":"secret token leaked in text","involvedObject":{"kind":"Pod","name":"auth","namespace":"app"}},
		{"type":"Warning","reason":"OOMKilled","message":"node","involvedObject":{"kind":"Node","name":"n1"}}
	]}`)
	got := ParseWarningEvents(raw)
	if len(got) != 2 {
		t.Fatalf("len %d %+v", len(got), got)
	}
	if got[0].Pod != "api" || got[0].Reason != "Unhealthy" || got[0].MessageOmitted {
		t.Fatalf("%+v", got[0])
	}
	if !got[1].MessageOmitted || got[1].Message != "" || got[1].Reason != "BackOff" {
		t.Fatalf("%+v", got[1])
	}
	if strings.Contains(got[1].Message, "token") {
		t.Fatal("token leaked")
	}
}
