// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExplainValidation(t *testing.T) {
	bad := [][]string{{}, {"--pid", "1"}, {"--node", "n", "--pid", "0"}, {"--pod", "api"}, {"--pod", "ns/api", "--namespace", "other"}, {"--all", "--limit", "0"}, {"--all", "--limit", "1001"}, {"--all", "--max-age", "0s"}, {"--all", "--format", "yaml"}, {"--destination", "example.com:443"}, {"--destination", "1.2.3.4:0"}, {"--dns", "example.com", "--node", "n", "--pid", "1"}, {"--dns", "."}, {"--all", "extra"}, {"--unknown"}, {"--node", " n"}}
	for _, args := range bad {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if _, e := parseExplain(args); e == nil {
				t.Fatalf("accepted invalid arguments: %v", args)
			}
		})
	}
}
func TestExplainSelectors(t *testing.T) {
	o, e := parseExplain([]string{"--pod", "prod/api", "--destination", "[2001:db8::1]:443"})
	if e != nil {
		t.Fatal(e)
	}
	if o.Namespace != "prod" || o.Pod != "api" || !o.destination("2001:0db8::1", 443) || o.destination("2001:db8::1", 80) {
		t.Fatal(o)
	}
	v, e := parseExplain([]string{"--destination", "::ffff:192.0.2.1"})
	if e != nil || !v.destination("192.0.2.1", 443) {
		t.Fatal(v, e)
	}
	d, e := parseExplain([]string{"--dns", "EXAMPLE.COM."})
	if e != nil || d.DNS != "example.com" {
		t.Fatal(d, e)
	}
}
func explainFixture() ([]explainAgent, time.Time) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	return []explainAgent{
		{Node: "node-b", ObservedAt: now, Events: []explainEvent{{explainIdentity: explainIdentity{Namespace: "prod", Pod: "api", PID: 42}, Action: "blocked", Reason: "port-deny"}}},
		{Node: "node-a", ObservedAt: now, Events: []explainEvent{{explainIdentity: explainIdentity{Namespace: "prod", Pod: "api", PID: 42, ContainerID: "container-exact"}, ObservedAt: now, Action: "blocked", Reason: "cidr-deny", Hook: "cgroup", DestinationIP: "192.0.2.1", DestinationPort: 443}, {explainIdentity: explainIdentity{Namespace: "dev", Pod: "api"}, Action: "observed"}}, TCP: []explainTCP{{explainIdentity: explainIdentity{Namespace: "prod", Pod: "api", PID: 42}, RemoteIP: "192.0.2.1", RemotePort: 443, ActiveEstablished: 1, Retransmissions: 2, RTOs: 1}}, DNS: []explainDNS{{Namespace: "prod", Pod: "api", Name: "example.com", Queries: 3, Responses: 2, Failures: 1}}},
	}, now
}
func TestExplainPIDNodeIsolation(t *testing.T) {
	a, now := explainFixture()
	o, e := parseExplain([]string{"--node", "node-a", "--pid", "42"})
	if e != nil {
		t.Fatal(e)
	}
	r := buildExplain(a, o, now)
	if r.FindingsTotal != 3 || r.AgentsConsidered != 1 {
		t.Fatalf("%+v", r)
	}
	for _, f := range r.Findings {
		if f.Node != "node-a" || f.Kind == "dns-counters" {
			t.Fatal(f)
		}
	}
	a[1].TCP[0].OwnershipStale = true
	r = buildExplain(a, o, now)
	if r.FindingsTotal != 1 {
		t.Fatal("stale socket ownership matched PID", r)
	}
}
func TestExplainNamespaceAndContainerIsolation(t *testing.T) {
	a, now := explainFixture()
	o, _ := parseExplain([]string{"--pod", "prod/api", "--container", "container-exact"})
	r := buildExplain(a, o, now)
	if r.FindingsTotal != 1 || r.Findings[0].Namespace != "prod" {
		t.Fatal(r)
	}
	o.Container = "container"
	if buildExplain(a, o, now).FindingsTotal != 0 {
		t.Fatal("container prefix matched")
	}
}
func TestExplainDestinationAndDNSBoundaries(t *testing.T) {
	a, now := explainFixture()
	o, _ := parseExplain([]string{"--destination", "192.0.2.1:443"})
	r := buildExplain(a, o, now)
	if r.FindingsTotal != 3 {
		t.Fatal(r)
	}
	o, _ = parseExplain([]string{"--dns", "EXAMPLE.COM."})
	r = buildExplain(a, o, now)
	if r.FindingsTotal != 1 || r.Findings[0].Kind != "dns-counters" {
		t.Fatal(r)
	}
	if !strings.Contains(r.Findings[0].NextCheck, "response codes") {
		t.Fatal(r)
	}
}
func TestExplainStaleUnknownAndFutureReports(t *testing.T) {
	a, now := explainFixture()
	o, _ := parseExplain([]string{"--all"})
	for _, stamp := range []time.Time{{}, now.Add(-3 * time.Minute), now.Add(2 * time.Minute)} {
		b := a[0]
		b.ObservedAt = stamp
		r := buildExplain([]explainAgent{b}, o, now)
		if r.AgentsExcluded != 1 || r.FindingsTotal != 0 || r.Status != "no-matching-evidence" {
			t.Fatal(r)
		}
	}
	a[0].Stale = true
	if buildExplain(a[:1], o, now).FindingsTotal != 0 {
		t.Fatal("stale report included")
	}
}
func TestExplainLimitAndNoEvidence(t *testing.T) {
	a, now := explainFixture()
	o, _ := parseExplain([]string{"--all", "--limit", "1"})
	r := buildExplain(a, o, now)
	if len(r.Findings) != 1 || !r.Truncated || r.FindingsTotal != 6 || r.Findings[0].Node != "node-a" {
		t.Fatal(r)
	}
	r = buildExplain(nil, o, now)
	var b bytes.Buffer
	if e := writeExplain(&b, r, "text"); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(b.String(), "No matching evidence") || strings.Contains(b.String(), "connection is healthy") {
		t.Fatal(b.String())
	}
}
func TestExplainReadContract(t *testing.T) {
	for _, input := range []string{`{}`, `{"items":null}`, `[]`, `{"items":{}}`, `{"items":[]} trailing`} {
		if _, e := readExplain(strings.NewReader(input)); e == nil {
			t.Fatal("accepted", input)
		}
	}
	a, e := readExplain(strings.NewReader(`{"items":[],"futureField":true}`))
	if e != nil || len(a) != 0 {
		t.Fatal(a, e)
	}
	if _, e := readExplain(io.LimitReader(zeroReader{}, explainMaxBytes+1)); e == nil || !strings.Contains(e.Error(), "exceeds") {
		t.Fatal(e)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type explainRoundTrip func(*http.Request) (*http.Response, error)

func (f explainRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type explainTrackedBody struct {
	io.Reader
	closed bool
}

func (b *explainTrackedBody) Close() error { b.closed = true; return nil }
func TestExplainFetchAuthenticationReadOnlyAndClose(t *testing.T) {
	t.Setenv("NETRA_API_KEY", "fixture-only")
	body := &explainTrackedBody{Reader: strings.NewReader(`{"items":[]}`)}
	client := &http.Client{Transport: explainRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/agents" || r.Header.Get("Authorization") != "Bearer fixture-only" || r.Header.Get("X-Netra-Actor") != "netractl" {
			t.Fatal(r)
		}
		return &http.Response{StatusCode: 200, Body: body, Header: http.Header{}}, nil
	})}
	if _, e := fetchExplain(client, "https://controller.example"); e != nil {
		t.Fatal(e)
	}
	if !body.closed {
		t.Fatal("body not closed")
	}
}
func TestExplainFetchErrors(t *testing.T) {
	for _, status := range []int{301, 401, 403, 500} {
		body := &explainTrackedBody{Reader: strings.NewReader("private backend response")}
		c := &http.Client{Transport: explainRoundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: body, Header: http.Header{}}, nil
		})}
		_, e := fetchExplain(c, "https://controller.example")
		if e == nil || strings.Contains(e.Error(), "private") || !body.closed {
			t.Fatal(e, body.closed)
		}
	}
	c := &http.Client{Transport: explainRoundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("network unavailable") })}
	if _, e := fetchExplain(c, "https://controller.example"); e == nil {
		t.Fatal("network error lost")
	}
}
func TestExplainTextEscapesAndJSON(t *testing.T) {
	a, now := explainFixture()
	a[1].Node = "node\x1b[31m"
	a[1].Events[0].Comm = "worker\nforged"
	o, _ := parseExplain([]string{"--all"})
	r := buildExplain(a, o, now)
	var b bytes.Buffer
	_ = writeExplain(&b, r, "text")
	if strings.ContainsRune(b.String(), '\x1b') || strings.Contains(b.String(), "worker\nforged") {
		t.Fatal("unescaped terminal data")
	}
	b.Reset()
	if e := writeExplain(&b, r, "json"); e != nil {
		t.Fatal(e)
	}
	var out explainReport
	if e := json.Unmarshal(b.Bytes(), &out); e != nil || out.FindingsTotal != r.FindingsTotal {
		t.Fatal(e, out)
	}
}
func TestExplainOfflineCLI(t *testing.T) {
	a, _ := explainFixture()
	for i := range a {
		a[i].ObservedAt = time.Now()
	}
	payload, _ := json.Marshal(map[string]any{"items": a})
	p := filepath.Join(t.TempDir(), "agents.json")
	if e := os.WriteFile(p, payload, 0600); e != nil {
		t.Fatal(e)
	}
	var b bytes.Buffer
	if e := explainCmd([]string{"--input", p, "--pod", "prod/api", "--format", "json"}, &b); e != nil {
		t.Fatal(e)
	}
	var r explainReport
	if e := json.Unmarshal(b.Bytes(), &r); e != nil || r.FindingsTotal != 5 {
		t.Fatal(e, r)
	}
	if strings.Contains(b.String(), p) {
		t.Fatal("local file path leaked into report")
	}
	if e := explainCmd([]string{"--help"}, io.Discard); e != nil {
		t.Fatal(e)
	}
}
