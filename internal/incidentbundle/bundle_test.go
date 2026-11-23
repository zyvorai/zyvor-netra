// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package incidentbundle

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/dnsdetect"
	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/models"
)

var update = flag.Bool("update", false, "rewrite testdata/golden.json")

var t0 = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// secrets are planted in every store fixture; none may reach a bundle.
var secrets = []string{
	"hunter2-PASSWORD", "sk_live_ABCDEF1234567890", "TOPSECRETBEARERVALUE1234", "AKIAIOSFODNN7EXAMPLE",
	"s3cr3t-cookie-value", "payload-bytes-GET-/admin", "ARGV-SECRET-FLAG", "ENV-DB-PASS-77", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP",
	"query-secret-9981", "userinfo-pass-42", "subdomain-exfil-label",
}

func ts(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

func fixture() Inputs {
	attach := &models.BPFAttachReport{Available: true, ObservedAt: ts(-1), Hash: "abc123", Total: 1, TCXSupported: true,
		Interfaces: []models.BPFInterfaceAttach{{Name: "eth0", Index: 2, Type: "ether", State: "up",
			TCXIngress: []models.BPFProgram{{ID: 11, Name: "netra_tc_in", Owner: models.BPFOwnerNetra}},
			XDP:        &models.BPFProgram{ID: 12, Name: "netra_xdp", Owner: models.BPFOwnerNetra, Mode: "native"}}}}
	agent := func(node string) models.AgentStatus {
		return models.AgentStatus{AgeSeconds: 3, AgentReport: models.AgentReport{
			Node: node, Mode: "observe", Interfaces: []string{"eth0", "lo"}, Hooks: []string{"tc"}, Standalone: true, AgentStartedAt: ts(-300), ObservedAt: ts(-1),
			Stats:     []models.DestinationStat{{DestinationIP: "203.0.113.9", Packets: 100, Bytes: 9000, Blocked: 2}},
			DNSHealth: []models.DNSHealthStat{{Name: "api.example.com", Queries: 10, Responses: 8, Failures: 2, MaxLatencyUS: 900, Namespace: "prod", WorkloadName: "web"}},
			TLSMetadata: []models.TLSMetadataStat{{SNI: "api.example.com", Handshakes: 7, Blocked: 1, Namespace: "prod", WorkloadName: "web"},
				{SNI: "evil.example/path?token=query-secret-9981", Handshakes: 1}},
			HTTPMetadata: []models.HTTPMetadataStat{{Method: "GET", Host: "svc.example.com", Requests: 5, Namespace: "prod", WorkloadName: "web"},
				{Method: "GET /admin?password=hunter2-PASSWORD", Host: "user:userinfo-pass-42@host.example", Requests: 1}},
			HTTPStatus: []models.HTTPStatusStat{{Status: 503, Count: 4, Namespace: "prod", WorkloadName: "web"}},
			Netlink:    &models.NetlinkReport{Available: true, Overruns: 1},
			BPFAttach:  attach,
		}}
	}
	return Inputs{
		Now: t0, Window: 30 * time.Minute, Version: "0.32.0", Mode: "observe",
		Agents: []models.AgentStatus{agent("node-b"), agent("node-a")},
		Config: models.EBPFFastPathConfig{Mode: "observe", BlockedIPv4: []string{"198.51.100.7"}, BlockedDNS: []string{"bad.example"}, Revision: 7},
		Metrics: []MetricLine{
			{Context: "ebpf.packets", Dimension: "observed", Units: "packets/s", Scope: "all", Start: t0.Unix() - 60, Step: 15, Values: []float64{10, 12, math.NaN(), 40}},
			{Context: "system.cpu", Dimension: "user", Units: "%", Scope: "all", Start: t0.Unix() - 60, Step: 15, Values: []float64{1, 2, 3, 4}},
		},
		Flows: []flowlog.Record{
			{ObservedAt: ts(-5), Node: "node-a", Namespace: "prod", WorkloadName: "web", Peer: "203.0.113.9", Port: 443, Protocol: "TCP", Direction: "egress", Packets: 10, Bytes: 5000, Comm: "curl", PID: 4242, DNSName: "subdomain-exfil-label.example.com", TLSSNI: "api.example.com"},
			{ObservedAt: ts(-4), Node: "node-a", Namespace: "prod", WorkloadName: "web", Peer: "203.0.113.9", Port: 443, Protocol: "TCP", Direction: "egress", Packets: 5, Bytes: 1000},
			{ObservedAt: ts(-100), Node: "node-a", Peer: "203.0.113.50", Port: 80, Protocol: "TCP", Direction: "egress", Bytes: 77},
		},
		FlowsOK: true,
		Netlink: []models.NetlinkEvent{
			{ObservedAt: ts(-10), Node: "node-a", Kind: "route", Action: "new", Destination: "10.1.0.0/24", Gateway: "10.0.0.1", Interface: "eth0", MAC: "aa:bb:cc:dd:ee:ff",
				Actor: &models.NetlinkActor{Confidence: "high", Comm: "ip", PID: 99}},
			{ObservedAt: ts(-9), Node: "node-a", Kind: "overrun", Action: "new", Detail: "ENOBUFS password=hunter2-PASSWORD"},
			{ObservedAt: ts(-200), Node: "node-a", Kind: "link", Action: "new", Interface: "old0"},
		},
		DNSOK: true,
		DNSFindings: []dnsdetect.Finding{{ID: "f1", Type: dnsdetect.FindingTunneling, Severity: dnsdetect.SevWarning, Domain: "tunnel.example", Subdomain: "subdomain-exfil-label",
			Score: 0.8123, Signals: []string{"high-entropy"}, Node: "node-a", Namespace: "prod", Workload: "web", FirstSeen: ts(-20), LastSeen: ts(-2), Count: 40,
			ExampleNames: []string{"subdomain-exfil-label.tunnel.example"}}},
		Audit: []models.AuditEvent{
			{At: ts(-8), Actor: "alice", Action: "ebpf.mode", Target: "cluster", Details: map[string]any{"mode": "enforce", "lease": 300, "password": "hunter2-PASSWORD",
				"body": "payload-bytes-GET-/admin", "cmdline": "ARGV-SECRET-FLAG", "env": "ENV-DB-PASS-77", "reason": "Authorization: Bearer TOPSECRETBEARERVALUE1234 see https://u:userinfo-pass-42@h.example/x?token=query-secret-9981", "nested": map[string]any{"k": "v"}}},
			{At: ts(-500), Actor: "bob", Action: "old.action"},
		},
		Leases: []models.DenyLease{{Owner: "ds1", Type: "cidr", Key: "egress|203.0.113.0/24", Summary: "deny egress 203.0.113.0/24", LeaseSeconds: 600, CreatedAt: ts(-7), CreatedBy: "alice", ExpiresAt: ts(3)}},
		LeaseHistory: []models.LeaseEvent{{At: ts(-7), Action: "create", Actor: "alice", Owner: "ds1", Rule: "egress|203.0.113.0/24", LeaseSeconds: 600},
			{At: ts(-6), Action: "reject", Actor: "bob", Owner: "ds2", Reason: "cookie: s3cr3t-cookie-value", Rails: []string{"catch-all"}}},
		Attach:      []models.BPFAttachFinding{{Severity: "warning", Kind: "hook-drift", Node: "node-a", Subject: "eth0", Message: "program replaced api_key=sk_live_ABCDEF1234567890", Interfaces: []string{"eth0"}}},
		Drops:       []models.DropDetectiveFinding{{Node: "node-a", Confidence: "high", Code: "policy", Stage: "tc-egress", Src: "10.0.0.5", Dst: "203.0.113.9", Packets: 33, Explanation: "dropped by deny rule; AKIAIOSFODNN7EXAMPLE", Comm: "curl", PID: 4242}},
		Alerts:      []AlertIn{{Rule: "conntrack-high", Node: "node-a", Context: "ebpf.conntrack_entries", Chart: "ebpf.conntrack_entries", Status: "critical", Value: 91, Units: "entries", Since: ts(-12), Info: "secret=sk_live_ABCDEF1234567890"}},
		Transitions: []TransitionIn{{At: ts(-12), Rule: "conntrack-high", Node: "node-a", Chart: "ebpf.conntrack_entries", From: "clear", To: "critical", Info: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP"}},
		AlertsOK:    true,
		Anomalies:   []AnomalyIn{{Node: "node-a", At: ts(-11), Rate: 55}, {Node: "node-a", At: ts(-10), Rate: 5}},
	}
}

func build(t *testing.T, in Inputs) ([]byte, *Bundle) {
	t.Helper()
	out, doc, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	return out, doc
}

func TestGoldenBundle(t *testing.T) {
	out, _ := build(t, fixture())
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, out, "", "  "); err != nil {
		t.Fatal(err)
	}
	pretty.WriteByte('\n')
	const path = "testdata/golden.json"
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, pretty.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, pretty.Bytes()) {
		t.Fatalf("bundle differs from %s (run go test ./internal/incidentbundle -update after reviewing the change)", path)
	}
	if rep := VerifyFile(want); !rep.OK {
		t.Fatalf("golden bundle fails verify: %v", rep.Problems)
	}
}

func TestDeterministic(t *testing.T) {
	a, _ := build(t, fixture())
	in := fixture()
	// Shuffle every store's order: the output must not change.
	in.Agents[0], in.Agents[1] = in.Agents[1], in.Agents[0]
	in.Flows[0], in.Flows[2] = in.Flows[2], in.Flows[0]
	in.Netlink[0], in.Netlink[2] = in.Netlink[2], in.Netlink[0]
	in.Metrics[0], in.Metrics[1] = in.Metrics[1], in.Metrics[0]
	b, _ := build(t, in)
	if !bytes.Equal(a, b) {
		t.Fatal("same window built in a different input order produced a different bundle")
	}
}

func TestNothingSecretSurvives(t *testing.T) {
	for _, mask := range []MaskMode{MaskNone, MaskIPs, MaskPrefix} {
		in := fixture()
		in.Opts.Mask = mask
		out, _ := build(t, in)
		for _, s := range secrets {
			if bytes.Contains(out, []byte(s)) {
				t.Fatalf("mask=%s: planted secret %q reached the bundle", mask, s)
			}
		}
		for _, banned := range []string{"aa:bb:cc:dd:ee:ff", "curl", "4242", "198.51.100.7", "bad.example"} {
			if mask == MaskNone && (banned == "198.51.100.7" || banned == "bad.example") {
				continue
			}
			if bytes.Contains(out, []byte(banned)) && (banned == "aa:bb:cc:dd:ee:ff" || banned == "198.51.100.7" || banned == "bad.example") {
				t.Fatalf("mask=%s: %q must not be in the bundle", mask, banned)
			}
		}
		if rep := VerifyFile(out); !rep.OK {
			t.Fatalf("mask=%s: own bundle fails verify: %v", mask, rep.Problems)
		}
	}
}

func TestPayloadShapedFieldsRefusedByVerify(t *testing.T) {
	out, _ := build(t, fixture())
	for _, inject := range []string{`"payload":"AAAA"`, `"cmdline":"x"`, `"password":"x"`, `"headers":"x"`} {
		bad := bytes.Replace(out, []byte(`{"available":true,"dnsFindings"`), []byte(`{`+inject+`,"available":true,"dnsFindings"`), 1)
		if bytes.Equal(bad, out) {
			t.Fatal("injection point not found")
		}
		if rep := VerifyFile(bad); rep.OK {
			t.Fatalf("verify accepted injected field %s", inject)
		}
	}
}

func TestAuditDetailsAllowList(t *testing.T) {
	_, doc := build(t, fixture())
	var a AuditSection
	if err := json.Unmarshal(doc.Sections[SecAudit], &a); err != nil {
		t.Fatal(err)
	}
	if len(a.Entries) != 1 {
		t.Fatalf("want 1 in-window audit entry, got %d", len(a.Entries))
	}
	d := a.Entries[0].Details
	for _, k := range []string{"password", "body", "cmdline", "env", "nested"} {
		if _, ok := d[k]; ok {
			t.Fatalf("audit detail %q must not be carried", k)
		}
	}
	if d["mode"] != "enforce" || d["lease"] != "300" {
		t.Fatalf("allow-listed details lost: %v", d)
	}
	if strings.Contains(d["reason"], "TOPSECRET") || strings.Contains(d["reason"], "query-secret") || strings.Contains(d["reason"], "userinfo-pass") {
		t.Fatalf("reason not scrubbed: %q", d["reason"])
	}
}

func TestRedactionBlockAndLists(t *testing.T) {
	_, doc := build(t, fixture())
	if doc.Redaction.Approach == "" || len(doc.Redaction.NeverIncluded) == 0 || len(doc.Redaction.Applied) == 0 {
		t.Fatalf("redaction block empty: %+v", doc.Redaction)
	}
	rules := map[string]bool{}
	for _, a := range doc.Redaction.Applied {
		rules[a.Rule] = true
	}
	for _, want := range []string{"url-credentials", "url-query", "credential-assignment", "bearer-token", "invalid-hostname"} {
		if !rules[want] {
			t.Errorf("redaction.applied lacks %q: %+v", want, doc.Redaction.Applied)
		}
	}
	var m MetadataSection
	_ = json.Unmarshal(doc.Sections[SecMetadata], &m)
	for _, f := range m.DNSFindings {
		if f.Domain != "tunnel.example" {
			t.Fatalf("dns finding domain %q", f.Domain)
		}
	}
	if len(m.DNSFindings) != 1 {
		t.Fatalf("want 1 dns finding got %d", len(m.DNSFindings))
	}
	for _, h := range m.HTTP {
		if h.Method != "GET" && h.Method != "OTHER" {
			t.Fatalf("method %q", h.Method)
		}
		if strings.ContainsAny(h.Host, "@?/ ") {
			t.Fatalf("host %q not reduced", h.Host)
		}
	}
}

func TestWindowFilterAndTimeline(t *testing.T) {
	_, doc := build(t, fixture())
	var n NetworkSection
	_ = json.Unmarshal(doc.Sections[SecNetwork], &n)
	if len(n.Events) != 2 {
		t.Fatalf("events outside the window must be dropped: %+v", n.Events)
	}
	var tl TimelineSection
	_ = json.Unmarshal(doc.Sections[SecTimeline], &tl)
	prev := ""
	sawState := false
	for _, e := range tl.Entries {
		if e.Category == "" || e.Severity == "" || e.Ref == "" {
			t.Fatalf("timeline entry missing category, severity or ref: %+v", e)
		}
		if e.AtKnown {
			if sawState || e.At < prev {
				t.Fatalf("timeline not sorted by time with state last: %+v", tl.Entries)
			}
			prev = e.At
		} else {
			sawState = true
		}
	}
	if tl.Counts["break"] == 0 || tl.Counts["change"] == 0 {
		t.Fatalf("counts %v", tl.Counts)
	}
}

func TestNodeScope(t *testing.T) {
	in := fixture()
	in.Node = "node-b"
	_, doc := build(t, in)
	if doc.Identity.Scope != "node" || doc.Identity.Nodes != 1 {
		t.Fatalf("identity %+v", doc.Identity)
	}
	var n NetworkSection
	_ = json.Unmarshal(doc.Sections[SecNetwork], &n)
	if len(n.Events) != 0 {
		t.Fatalf("node-a events leaked into a node-b bundle: %+v", n.Events)
	}
}

func TestExclude(t *testing.T) {
	in := fixture()
	in.Opts.Exclude = []string{"audit", "flows"}
	out, doc := build(t, in)
	if !contains(doc.Redaction.ExcludedSections, "audit") || bytes.Contains(doc.Sections[SecAudit], []byte("alice")) {
		t.Fatal("audit not excluded")
	}
	if bytes.Contains(doc.Sections[SecTimeline], []byte(`"category":"audit"`)) {
		t.Fatal("timeline still carries audit entries")
	}
	if rep := VerifyFile(out); !rep.OK {
		t.Fatalf("%v", rep.Problems)
	}
	in.Opts.Exclude = []string{"nope"}
	if _, _, err := Build(in); err == nil {
		t.Fatal("unknown section accepted")
	}
}

func TestMaskStableAndPrefixPreserving(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	r := NewRedactor(MaskIPs, key)
	a := r.String("peer 203.0.113.9 and again 203.0.113.9/24 and 2001:db8::1")
	if strings.Contains(a, "203.0.113.9") || strings.Contains(a, "2001:db8") {
		t.Fatalf("not masked: %s", a)
	}
	parts := strings.Fields(a)
	if parts[1] != strings.TrimSuffix(parts[4], "/24") {
		t.Fatalf("same address masked two ways: %s", a)
	}
	first, second := NewRedactor(MaskIPs, key), NewRedactor(MaskIPs, key)
	if first.String("203.0.113.9") != second.String("203.0.113.9") {
		t.Fatal("same key must give the same pseudonym")
	}
	if NewRedactor(MaskIPs, []byte("another key another key another!")).String("203.0.113.9") == NewRedactor(MaskIPs, key).String("203.0.113.9") {
		t.Fatal("different keys gave the same pseudonym")
	}
	if NewRedactor(MaskIPs, key).KeyID() != NewRedactor(MaskPrefix, key).KeyID() || NewRedactor(MaskIPs, key).KeyID() == "" {
		t.Fatal("key id")
	}

	p := NewRedactor(MaskPrefix, key)
	mask := func(s string) netip.Addr { return netip.MustParseAddr(p.String(s)) }
	m1, m2, m3 := mask("10.1.2.3"), mask("10.1.2.200"), mask("192.168.0.1")
	common := func(x, y netip.Addr) int {
		bx, by := x.AsSlice(), y.AsSlice()
		n := 0
		for i := range bx {
			for bit := 7; bit >= 0; bit-- {
				if (bx[i]>>bit)&1 != (by[i]>>bit)&1 {
					return n
				}
				n++
			}
		}
		return n
	}
	if got := common(m1, m2); got != 24 {
		t.Fatalf("10.1.2.3 and 10.1.2.200 share 24 bits in, got %d out (%s %s)", got, m1, m2)
	}
	if common(m1, m3) > 8 {
		t.Fatalf("unrelated addresses share too long a prefix: %s %s", m1, m3)
	}
	if m1.String() == "10.1.2.3" {
		t.Fatal("prefix mode returned the input")
	}
	v6a, v6b := mask("2001:db8::1"), mask("2001:db8::2")
	if !v6a.Is6() || common(v6a, v6b) < 120 {
		t.Fatalf("v6 prefix: %s %s", v6a, v6b)
	}
}

func TestBoundsAndTruncation(t *testing.T) {
	in := fixture()
	for i := 0; i < 900; i++ {
		in.Netlink = append(in.Netlink, models.NetlinkEvent{ObservedAt: ts(-(i % 25)), Node: "node-a", Kind: "neighbor", Action: "new", Address: fmt.Sprintf("10.9.%d.%d", i/200, i%200), Interface: "eth0", Sequence: uint64(i)})
		in.Audit = append(in.Audit, models.AuditEvent{At: ts(-(i % 25)), Actor: "u", Action: fmt.Sprintf("act%d", i)})
		in.Flows = append(in.Flows, flowlog.Record{ObservedAt: ts(-3), Node: "node-a", Peer: fmt.Sprintf("203.0.%d.%d", i/250, i%250), Port: 443, Protocol: "TCP", Direction: "egress", Bytes: uint64(i + 1)})
	}
	for i := 0; i < 200; i++ {
		in.Metrics = append(in.Metrics, MetricLine{Context: "c", Dimension: fmt.Sprintf("d%03d", i), Scope: "all", Step: 1, Values: make([]float64, 500)})
	}
	out, doc := build(t, in)
	var n NetworkSection
	_ = json.Unmarshal(doc.Sections[SecNetwork], &n)
	if len(n.Events) != MaxNetEvents || !hasTrunc(n.Truncated, "events") {
		t.Fatalf("network events %d truncated=%v", len(n.Events), n.Truncated)
	}
	var m MetricsSection
	_ = json.Unmarshal(doc.Sections[SecMetrics], &m)
	if len(m.Series) != MaxSeries || len(m.Series[0].Values) != MaxPoints {
		t.Fatalf("series %d points %d", len(m.Series), len(m.Series[0].Values))
	}
	var f FlowsSection
	_ = json.Unmarshal(doc.Sections[SecFlows], &f)
	if len(f.Flows) != MaxFlows || !hasTrunc(f.Truncated, "flows") {
		t.Fatalf("flows %d %v", len(f.Flows), f.Truncated)
	}
	if rep := VerifyFile(out); !rep.OK {
		t.Fatalf("%v", rep.Problems)
	}

	// Total size bound: a tiny budget forces further truncation, never overflow.
	in.Opts.MaxBytes = 120 << 10
	out, doc = build(t, in)
	if doc.Bounds.Bytes > 120<<10 {
		t.Fatalf("bundle is %d bytes over its %d bound", doc.Bounds.Bytes, 120<<10)
	}
	if !strings.Contains(string(out), `"kept"`) {
		t.Fatal("no truncation recorded")
	}
	if rep := VerifyFile(out); !rep.OK {
		t.Fatalf("shrunk bundle fails verify: %v", rep.Problems)
	}
	// A request can never raise the bound.
	in.Opts.MaxBytes = 1 << 40
	if _, doc := build(t, in); doc.Bounds.MaxTotalBytes != MaxTotalBytes {
		t.Fatal("bound raised")
	}
	for _, w := range []time.Duration{0, 30 * time.Second, 25 * time.Hour} {
		in.Window = w
		if _, _, err := Build(in); err == nil {
			t.Fatalf("window %s accepted", w)
		}
	}
}

func hasTrunc(ts []Trunc, list string) bool {
	for _, t := range ts {
		if t.List == list && t.Total > t.Kept {
			return true
		}
	}
	return false
}

func TestHostileInputs(t *testing.T) {
	in := fixture()
	huge := strings.Repeat("A", 1<<20)
	in.Audit = append(in.Audit, models.AuditEvent{At: ts(-1), Actor: huge, Action: "x\x00\x1b[31my\xff\xfe", Target: "\n\r\t", Details: map[string]any{"reason": huge, "mode": "m\x00"}})
	in.Netlink = append(in.Netlink, models.NetlinkEvent{ObservedAt: ts(-1), Node: "node-a", Kind: huge, Action: "new", Interface: "../../etc/passwd\x00"})
	in.Alerts = append(in.Alerts, AlertIn{Rule: huge, Node: "node-a", Status: "critical", Value: math.NaN(), Since: time.Time{}})
	in.Metrics = append(in.Metrics, MetricLine{Context: "z", Dimension: "inf", Scope: "all", Step: 0, Values: []float64{math.Inf(1), math.NaN(), -1}})
	in.Flows = append(in.Flows, flowlog.Record{ObservedAt: ts(-1), Node: "node-a", Peer: "::ffff:1.2.3.4%eth0", Port: 0, Protocol: "weird\x00"})
	out, _ := build(t, in)
	if bytes.Contains(out, []byte("\x00")) || bytes.Contains(out, []byte(strings.Repeat("A", 400))) {
		t.Fatal("hostile string survived")
	}
	if rep := VerifyFile(out); !rep.OK {
		t.Fatalf("hostile-input bundle fails verify: %v", rep.Problems)
	}
	for _, bad := range [][]byte{nil, []byte("{"), []byte("null"), []byte(`{"schema":"netra-incident-bundle/1"}`), bytes.Repeat([]byte("["), 1000), {0x1f, 0x8b, 0x00}} {
		if VerifyFile(bad).OK {
			t.Fatalf("verify accepted %q", bad)
		}
	}
}

func TestVerifyCatchesTampering(t *testing.T) {
	out, _ := build(t, fixture())
	if rep := VerifyFile(out); !rep.OK {
		t.Fatalf("%v", rep.Problems)
	}
	mutations := map[string]func(string) string{
		"edit a value": func(s string) string { return strings.Replace(s, `"actor":"alice"`, `"actor":"mallory"`, 1) },
		"schema version": func(s string) string {
			return strings.Replace(s, `netra-incident-bundle/1`, `netra-incident-bundle/2`, 1)
		},
		"edit the window":      func(s string) string { return strings.Replace(s, `"minutes":30`, `"minutes":31`, 1) },
		"edit identity":        func(s string) string { return strings.Replace(s, `"version":"0.32.0"`, `"version":"9.9.9"`, 1) },
		"weaken the redaction": func(s string) string { return strings.Replace(s, `"maskIps":"none"`, `"maskIps":"ips"`, 1) },
		"drop a hash":          func(s string) string { return strings.Replace(s, `"head":"`, `"head":"0`, 1) },
		"plant a secret":       func(s string) string { return strings.Replace(s, `"actor":"alice"`, `"actor":"password=hunter2"`, 1) },
		"plant a bearer": func(s string) string {
			return strings.Replace(s, `"actor":"alice"`, `"actor":"Bearer abcdefghijklmnop"`, 1)
		},
		"unknown top-level field": func(s string) string { return strings.Replace(s, `{"schema"`, `{"extra":1,"schema"`, 1) },
		"url with query": func(s string) string {
			return strings.Replace(s, `"actor":"alice"`, `"actor":"http://h.example/p?a=b"`, 1)
		},
		"oversized window": func(s string) string {
			return strings.Replace(strings.Replace(s, `"minutes":30`, `"minutes":2000`, 1), `"start":"2026-11-20T11:30:00Z"`, `"start":"2026-11-18T11:30:00Z"`, 1)
		},
	}
	for name, mut := range mutations {
		bad := mut(string(out))
		if bad == string(out) {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if rep := VerifyFile([]byte(bad)); rep.OK {
			t.Errorf("%s: verify accepted a tampered bundle", name)
		}
	}
	// Reordering a section's content (not just changing it) also breaks the chain.
	var doc Bundle
	_ = json.Unmarshal(out, &doc)
	doc.Integrity.Chain[0], doc.Integrity.Chain[1] = doc.Integrity.Chain[1], doc.Integrity.Chain[0]
	swapped, _ := json.Marshal(doc)
	if VerifyFile(swapped).OK {
		t.Error("swapped chain links accepted")
	}
	delete(doc.Sections, SecAudit)
	missing, _ := json.Marshal(doc)
	if VerifyFile(missing).OK {
		t.Error("missing section accepted")
	}
}

func TestMaskedBundleVerifiesAndLeakCaught(t *testing.T) {
	in := fixture()
	in.Opts.Mask = MaskIPs
	out, _ := build(t, in)
	if rep := VerifyFile(out); !rep.OK {
		t.Fatalf("%v", rep.Problems)
	}
	bad := strings.Replace(string(out), `"actor":"alice"`, `"actor":"alice 203.0.113.9"`, 1)
	if VerifyFile([]byte(bad)).OK {
		t.Fatal("an unmasked address in a masked bundle was accepted")
	}
}

func TestTarGzRoundTrip(t *testing.T) {
	out, _ := build(t, fixture())
	tgz, err := WriteTarGz(out)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := WriteTarGz(out)
	if !bytes.Equal(tgz, again) {
		t.Fatal("archive is not deterministic")
	}
	if rep := VerifyFile(tgz); !rep.OK {
		t.Fatalf("%v", rep.Problems)
	}
	// Flip one byte inside the compressed stream, or recompress with an edited member.
	bad := append([]byte(nil), tgz...)
	bad[len(bad)/2] ^= 0xff
	if VerifyFile(bad).OK {
		t.Fatal("corrupted archive accepted")
	}
	doc, _, _ := Load(tgz)
	edited := bytes.Replace(doc, []byte(`"alice"`), []byte(`"alicf"`), 1)
	if bytes.Equal(edited, doc) {
		t.Fatal("no edit")
	}
	if VerifyFile(edited).OK {
		t.Fatal("edited bundle accepted")
	}
}

func TestDiffDeterministicAndMeaningful(t *testing.T) {
	a, _ := build(t, fixture())
	again, _ := build(t, fixture())
	d0, err := Diff(a, again)
	if err != nil {
		t.Fatal(err)
	}
	if !d0.Identical {
		t.Fatalf("same inputs differ: %+v", d0.Sections)
	}
	in := fixture()
	in.Now = t0.Add(5 * time.Minute)
	in.Netlink = append(in.Netlink, models.NetlinkEvent{ObservedAt: ts(1), Node: "node-a", Kind: "route", Action: "delete", Destination: "10.1.0.0/24", Interface: "eth0"})
	in.Metrics[0].Values = []float64{100, 200}
	in.Config.BlockedIPv4 = append(in.Config.BlockedIPv4, "198.51.100.8")
	in.Opts.Mask = MaskNone
	bb, _ := build(t, in)
	d1, err := Diff(a, bb)
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := Diff(a, bb)
	j1, _ := json.Marshal(d1)
	j2, _ := json.Marshal(d2)
	if !bytes.Equal(j1, j2) {
		t.Fatal("diff is not deterministic")
	}
	if d1.Identical {
		t.Fatal("different bundles reported identical")
	}
	var sawEvent, sawMetric, sawDeny bool
	for _, s := range d1.Sections {
		for _, l := range s.Lists {
			if s.Section == SecNetwork && l.AddedTotal == 1 {
				sawEvent = true
			}
			if s.Section == SecMetrics && l.ChangedTotal > 0 {
				sawMetric = true
			}
		}
		for _, f := range s.Fields {
			if s.Section == SecEBPF && strings.Contains(f.Path, "blockedIPv4") && f.A == "1" && f.B == "2" {
				sawDeny = true
			}
		}
	}
	if !sawEvent || !sawMetric || !sawDeny {
		t.Fatalf("diff missed event=%v metric=%v deny=%v: %s", sawEvent, sawMetric, sawDeny, j1)
	}
	if _, err := Diff(a, []byte(`{"schema":"x"}`)); err == nil {
		t.Fatal("diff accepted a foreign document")
	}
}

func TestSecretRulesCatchSamples(t *testing.T) {
	for _, s := range []string{"password=abc123", "Authorization: Bearer abcdefghij", "AKIAIOSFODNN7EXAMPLE", "ghp_abcdefghijklmnopqrstuvwxyz0123",
		"-----BEGIN RSA PRIVATE KEY-----", "https://u:p@h.example/", "https://h.example/a?b=c", "xoxb-1234567890-abcdef", "token: abcdef"} {
		if len(scanString(s)) == 0 {
			t.Errorf("scan missed %q", s)
		}
		r := NewRedactor(MaskNone, nil)
		if out := r.String(s); len(scanString(out)) != 0 {
			t.Errorf("scrub left %q -> %q", s, out)
		}
	}
	for _, ok := range []string{"conntrack table 91% full", "route new 10.1.0.0/24 via 10.0.0.1 dev eth0", "token bucket exhausted", "https://h.example/path"} {
		if p := scanString(ok); len(p) != 0 {
			t.Errorf("false positive on %q: %v", ok, p)
		}
	}
}
