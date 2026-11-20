// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package nodeiso

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestABISizesMatchC(t *testing.T) {
	for name, tc := range map[string]struct {
		v    any
		size int
	}{
		"config":    {config{}, 16},
		"ruleKey":   {ruleKey{}, 8},
		"rule":      {rule{}, 24},
		"exemptKey": {exemptKey{}, 8},
		"destKey":   {destKey{}, 20},
		"destValue": {destValue{}, 16},
	} {
		if got := binary.Size(tc.v); got != tc.size {
			t.Errorf("%s: size %d, C ABI is %d", name, got, tc.size)
		}
	}
}

func TestEncodeRule(t *testing.T) {
	r, err := encodeRule(models.NodeIsolationRule{CIDR: "10.96.0.0/12", Protocol: "tcp", PortFrom: 443})
	if err != nil {
		t.Fatal(err)
	}
	if r.Family != afInet || r.Protocol != ipTCP || r.PrefixLen != 12 || r.PortStart != 443 || r.PortEnd != 443 {
		t.Fatalf("unexpected v4 rule %+v", r)
	}
	if r.Address[0] != 10 || r.Address[1] != 96 || r.Address[4] != 0 {
		t.Fatalf("v4 address must sit in the first four bytes, got %v", r.Address)
	}
	r, err = encodeRule(models.NodeIsolationRule{CIDR: "2001:db8::/32", PortFrom: 8000, PortTo: 8100})
	if err != nil {
		t.Fatal(err)
	}
	if r.Family != afInet6 || r.Protocol != 0 || r.PrefixLen != 32 || r.PortEnd != 8100 || r.Address[0] != 0x20 {
		t.Fatalf("unexpected v6 rule %+v", r)
	}
	if _, err := encodeRule(models.NodeIsolationRule{CIDR: "10.0.0.0/8", Protocol: "sctp"}); err == nil {
		t.Fatal("sctp must be rejected")
	}
}

func TestCompileAddsImplicitAndExemptions(t *testing.T) {
	spec := &models.NodeIsolationSpec{Mode: models.NodeIsolationShadow, Rules: []models.NodeIsolationRule{{CIDR: "10.0.0.0/8"}}, ExemptLocalPorts: []uint16{22}}
	rules, exempt, err := compile(spec, []models.NodeIsolationRule{{CIDR: "192.0.2.10/32", Protocol: "tcp", PortFrom: 30870}}, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[1].PortStart != 30870 {
		t.Fatalf("implicit rule must follow operator rules: %+v", rules)
	}
	if len(exempt) != 2 || exempt[0].Generation != 7 || exempt[0].Port != 22 || exempt[0].Protocol != ipTCP || exempt[1].Protocol != ipUDP {
		t.Fatalf("exempt keys: %+v", exempt)
	}
	many := make([]models.NodeIsolationRule, MaxRules+1)
	for i := range many {
		many[i] = models.NodeIsolationRule{CIDR: "10.0.0.0/8"}
	}
	if _, _, err := compile(&models.NodeIsolationSpec{Rules: many}, nil, 1); err == nil {
		t.Fatal("more than MaxRules must be refused")
	}
	if r, e, err := compile(nil, nil, 1); err != nil || r != nil || e != nil {
		t.Fatal("nil spec compiles to nothing")
	}
}

func TestModeForDemotes(t *testing.T) {
	until := time.Now().Add(time.Minute)
	enforce := &models.NodeIsolationSpec{Mode: models.NodeIsolationEnforce, LeaseUntil: &until}
	if ModeFor(nil, "") != ModeOff || ModeFor(enforce, "") != ModeEnforce || ModeFor(enforce, "controller stale") != ModeShadow {
		t.Fatal("mode mapping")
	}
	if ModeFor(&models.NodeIsolationSpec{Mode: models.NodeIsolationShadow}, "") != ModeShadow {
		t.Fatal("shadow stays shadow")
	}
}

func TestNextGenerationSkipsZero(t *testing.T) {
	if nextGeneration(0) != 1 || nextGeneration(^uint32(0)) != 1 || nextGeneration(5) != 6 {
		t.Fatal("generation wrap")
	}
}

func TestTopDests(t *testing.T) {
	got := topDests([]models.NodeIsolationDest{{Address: "a", Bytes: 1}, {Address: "b", Bytes: 9}, {Address: "c", Bytes: 5}}, 2)
	if len(got) != 2 || got[0].Address != "b" || got[1].Address != "c" {
		t.Fatalf("top: %+v", got)
	}
	if destAddress(destKey{Family: afInet, Address: [16]byte{8, 8, 8, 8}}) != "8.8.8.8" {
		t.Fatal("v4 dest address")
	}
}
