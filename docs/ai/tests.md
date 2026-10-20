# AI tests (netra)

_Generated 2026-10-20 by claude-opus-5-5 from a snapshot of tracked sources; verify before acting._

# Netra: eight high-value unit tests for untested code

## Selection

I picked eight units from the code shown that have **no visible tests**. Each one guards a safety boundary or a cross-component contract.

| # | Unit | Why it matters |
|---|---|---|
| 1 | `chatops.VerifySlackSignature` | Inbound ChatOps authentication and replay protection |
| 2 | `api.principal.Allows` / `allowsDim` / `Unrestricted` / `AllowsNamespace` | Scoped RBAC. An empty resource field must be denied when that dimension is restricted. |
| 3 | `l7.Degraded` | "Quiet L7 feed" must never read as "no activity". Detection is by name absence, not by `Attached:false`. |
| 4 | `netractl` `bpfMapsMissingFinding` / `rateDropFinding` / `includesRateDrops` | The Go side of a classifier the code says must stay aligned with `web/src/lib/bpfhealth.ts`. Only the web side is tested. |
| 5 | `flowlog.Class`, `ParseBackend`, `Options.Normalize`, `OptionsFromEnv`, `BackendFromEnv` | Retention knobs. Invalid environment values must fall back to safe defaults. |
| 6 | `counterfactual.MemoryStore.Query` | The window contract (Start inclusive, End exclusive), ordering, limit applied after sorting, and concurrency safety |
| 7 | `notify.Title` / `Plain` / `SMSBody` | The alert body seen by on-call staff, including dedup of Card/Text and the SMS length cap |
| 8 | `web/src/lib/incidents.ts` `rankSignals` / `visibleSignals` | Truncated incident lists must never hide the worst signal |

### Assumptions (flagged)

- **`notify.Event`:** this is a struct with string fields `Severity`, `Kind`, `Subject`, `Source`, `Message`, `Card`, `Text`, `Node` and `Fingerprint`. That is inferred from `format.go` and `webhook_adapter.go`. Its definition is not shown.
- **`api.principal`:** this has `[]string` fields `Namespaces`, `Clusters` and `Tenants`. That is inferred from `scope.go`. The test file name avoids a possible existing `scope_test.go`.
- **`netractl.explainOptions`:** this has string fields `Namespace`, `Pod`, `Container`, `Docker` and `DNS`, plus a numeric `PID`. That is inferred from `includesRateDrops`.
- **`counterfactual.Flow`:** this has a `time.Time` field `Timestamp`. The workload-filter case assumes the zero `WorkloadRef.Key()` is not the literal string `"no-such-workload"`.
- **`flowlog.DefaultRetain` / `DefaultMax`:** these constants are assumed to be positive, as `Normalize` implies.

---

## 1. `internal/chatops/signature_test.go`

```go
// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package chatops

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

func slackSign(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + ts + ":"))
	mac.Write(body)
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySlackSignature(t *testing.T) {
	const secret = "8f742231b10e8888abcd99yyyzzz85a5"
	now := time.Unix(1_700_000_000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	body := []byte("token=x&command=%2Fnetra&text=status")
	good := slackSign(secret, ts, body)

	t.Run("valid signature accepted", func(t *testing.T) {
		if err := VerifySlackSignature(secret, ts, body, good, now); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("empty signing secret refused even with a matching mac", func(t *testing.T) {
		if err := VerifySlackSignature("", ts, body, slackSign("", ts, body), now); err == nil {
			t.Fatal("expected refusal when no signing secret is configured")
		}
	})
	t.Run("wrong secret rejected", func(t *testing.T) {
		if err := VerifySlackSignature(secret, ts, body, slackSign("other", ts, body), now); err == nil {
			t.Fatal("expected mismatch")
		}
	})
	t.Run("tampered body rejected", func(t *testing.T) {
		if err := VerifySlackSignature(secret, ts, []byte("token=x&text=deny"), good, now); err == nil {
			t.Fatal("expected mismatch for a modified body")
		}
	})
	t.Run("timestamp is part of the mac", func(t *testing.T) {
		ts2 := strconv.FormatInt(now.Unix()+1, 10)
		if err := VerifySlackSignature(secret, ts2, body, good, now); err == nil {
			t.Fatal("signature for one timestamp must not validate another")
		}
	})
	t.Run("missing v0= prefix rejected", func(t *testing.T) {
		if err := VerifySlackSignature(secret, ts, body, good[len("v0="):], now); err == nil {
			t.Fatal("expected mismatch without the version prefix")
		}
	})
	t.Run("non-numeric timestamp rejected", func(t *testing.T) {
		if err := VerifySlackSignature(secret, "yesterday", body, good, now); err == nil {
			t.Fatal("expected invalid timestamp error")
		}
	})
	t.Run("replay window", func(t *testing.T) {
		cases := []struct {
			name   string
			offset time.Duration // request timestamp relative to now
			ok     bool
		}{
			{"exactly 5m old is accepted", -5 * time.Minute, true},
			{"4m in the future (clock skew) accepted", 4 * time.Minute, true},
			{"6m old rejected", -6 * time.Minute, false},
			{"6m in the future rejected", 6 * time.Minute, false},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				rts := strconv.FormatInt(now.Add(c.offset).Unix(), 10)
				err := VerifySlackSignature(secret, rts, body, slackSign(secret, rts, body), now)
				if c.ok && err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !c.ok && err == nil {
					t.Fatal("expected replay-window rejection")
				}
			})
		}
	})
}
```

## 2. `internal/api/principal_scope_test.go`

```go
// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import "testing"

func TestPrincipalUnrestrictedAllowsEverything(t *testing.T) {
	p := principal{}
	if !p.Unrestricted() {
		t.Fatal("zero principal must be unrestricted")
	}
	for _, c := range [][3]string{{"", "", ""}, {"prod", "east", "acme"}} {
		if !p.Allows(c[0], c[1], c[2]) {
			t.Fatalf("unrestricted principal denied %v", c)
		}
	}
	if !p.AllowsNamespace("") {
		t.Fatal("unrestricted principal must allow an empty namespace")
	}
}

func TestPrincipalNamespaceScope(t *testing.T) {
	p := principal{Namespaces: []string{"prod", "payments"}}
	if p.Unrestricted() {
		t.Fatal("namespace-scoped principal reported unrestricted")
	}
	for _, ns := range []string{"prod", "PROD", "  payments  "} {
		if !p.Allows(ns, "", "") || !p.AllowsNamespace(ns) {
			t.Errorf("expected %q allowed (case-insensitive, trimmed)", ns)
		}
	}
	for _, ns := range []string{"dev", "", "   ", "prod-2"} {
		if p.Allows(ns, "", "") || p.AllowsNamespace(ns) {
			t.Errorf("expected %q denied", ns)
		}
	}
}

func TestPrincipalEveryDimensionMustPass(t *testing.T) {
	p := principal{Namespaces: []string{"prod"}, Clusters: []string{"east"}, Tenants: []string{"acme"}}
	if !p.Allows("prod", "East", "ACME") {
		t.Fatal("all dimensions match; expected allow")
	}
	cases := [][3]string{
		{"dev", "east", "acme"},
		{"prod", "west", "acme"},
		{"prod", "east", "contoso"},
		{"prod", "", "acme"},  // empty cluster on a cluster-scoped principal
		{"prod", "east", ""},  // empty tenant on a tenant-scoped principal
	}
	for _, c := range cases {
		if p.Allows(c[0], c[1], c[2]) {
			t.Errorf("expected deny for %v", c)
		}
	}
}

func TestPrincipalClusterOnlyLeavesNamespaceOpen(t *testing.T) {
	p := principal{Clusters: []string{"east"}}
	if p.Unrestricted() {
		t.Fatal("cluster-scoped principal reported unrestricted")
	}
	if !p.Allows("", "east", "") {
		t.Fatal("unrestricted namespace/tenant must accept empty values")
	}
	if p.Allows("prod", "west", "") {
		t.Fatal("wrong cluster must be denied")
	}
}

func TestLocalClusterAndTenantTrimEnv(t *testing.T) {
	t.Setenv("NETRA_CLUSTER_NAME", "  prod-east \n")
	t.Setenv("NETRA_CLUSTER_TENANT", " acme ")
	if got := localCluster(); got != "prod-east" {
		t.Fatalf("localCluster=%q", got)
	}
	if got := localTenant(); got != "acme" {
		t.Fatalf("localTenant=%q", got)
	}
}
```

## 3. `internal/l7/degraded_test.go`

```go
// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7

import (
	"reflect"
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func agentWith(node string, stale bool, progs ...models.BPFProgramStat) models.AgentStatus {
	return models.AgentStatus{Stale: stale, AgentReport: models.AgentReport{Node: node, Programs: progs}}
}

var (
	l7In  = models.BPFProgramStat{Name: "netra_l7_cgroup_ingress", Attached: true}
	l7Eg  = models.BPFProgramStat{Name: "netra_l7_cgroup_egress", Attached: true}
	other = models.BPFProgramStat{Name: "netra_egress", Attached: true}
)

func TestDegradedNoAgents(t *testing.T) {
	d, nodes := Degraded(nil)
	if d || nodes != nil {
		t.Fatalf("got %v %v", d, nodes)
	}
}

func TestDegradedAllProgramsPresent(t *testing.T) {
	d, nodes := Degraded([]models.AgentStatus{agentWith("n1", false, l7In, l7Eg, other)})
	if d || len(nodes) != 0 {
		t.Fatalf("got %v %v", d, nodes)
	}
}

func TestDegradedWhenEgressRemovedAfterVerifierFailure(t *testing.T) {
	d, nodes := Degraded([]models.AgentStatus{agentWith("n1", false, l7In, other)})
	if !d || !reflect.DeepEqual(nodes, []string{"n1"}) {
		t.Fatalf("got %v %v", d, nodes)
	}
}

// Presence by name is the contract; Attached:false alone is not degraded.
func TestDegradedIgnoresAttachedFlag(t *testing.T) {
	in := l7In
	in.Attached = false
	d, _ := Degraded([]models.AgentStatus{agentWith("n1", false, in, l7Eg)})
	if d {
		t.Fatal("present-but-unattached program must not be reported as name-absent")
	}
}

func TestDegradedSkipsStaleAgents(t *testing.T) {
	d, nodes := Degraded([]models.AgentStatus{agentWith("stale-node", true)})
	if d || len(nodes) != 0 {
		t.Fatalf("stale agent counted: %v %v", d, nodes)
	}
}

func TestDegradedListsNodeOnceAndSorted(t *testing.T) {
	d, nodes := Degraded([]models.AgentStatus{
		agentWith("zeta", false),              // both L7 programs missing: listed once
		agentWith("alpha", false, l7Eg),       // ingress missing
		agentWith("mid", false, l7In, l7Eg),   // healthy
	})
	if !d || !reflect.DeepEqual(nodes, []string{"alpha", "zeta"}) {
		t.Fatalf("got %v %v", d, nodes)
	}
}
```

## 4. `cmd/netractl/bpfhealth_test.go`

```go
// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "testing"

// These strings must stay identical to web/src/lib/bpfhealth.ts.
const (
	wantMissingNext = "Rebuild and roll the agent image so allow/rate/icmp maps exist. Until then those controls fail open."
	wantRateNext    = "Check whether this destination's PPS ceiling is set too low for legitimate traffic; rate-drop counters are cumulative since the map was created and do not identify which flows were dropped or when."
)

func TestBPFMapsMissingFindingEmpty(t *testing.T) {
	for _, in := range [][]string{nil, {}} {
		k, e, n := bpfMapsMissingFinding(in)
		if k != "" || e != "" || n != "" {
			t.Fatalf("%v: got %q %q %q", in, k, e, n)
		}
	}
}

func TestBPFMapsMissingFinding(t *testing.T) {
	k, e, n := bpfMapsMissingFinding([]string{"icmp_errors", "allowed_uids"})
	if k != "bpf-maps-missing" {
		t.Fatalf("kind=%q", k)
	}
	if e != `missing-maps="icmp_errors,allowed_uids"` {
		t.Fatalf("evidence=%q", e)
	}
	if n != wantMissingNext {
		t.Fatalf("next drifted from web copy: %q", n)
	}
}

func TestRateDropFinding(t *testing.T) {
	if k, e, n := rateDropFinding(explainNamedCount{Name: "203.0.113.5", Count: 0}); k != "" || e != "" || n != "" {
		t.Fatalf("zero count produced a finding: %q %q %q", k, e, n)
	}
	k, e, n := rateDropFinding(explainNamedCount{Name: "203.0.113.5", Count: 42})
	if k != "rate-drop" || e != `destination="203.0.113.5" dropped=42` || n != wantRateNext {
		t.Fatalf("got %q %q %q", k, e, n)
	}
}

func TestIncludesRateDropsOnlyWhenUnscoped(t *testing.T) {
	if !(explainOptions{}).includesRateDrops() {
		t.Fatal("node-wide explain must include rate drops")
	}
	scoped := []explainOptions{
		{Namespace: "prod"}, {Pod: "api-1"}, {PID: 42},
		{Container: "abc"}, {Docker: "web"}, {DNS: "example.com"},
	}
	for _, o := range scoped {
		if o.includesRateDrops() {
			t.Errorf("scoped explain %+v must not include node-wide rate drops", o)
		}
	}
}
```

## 5. `internal/flowlog/flowlog_helpers_test.go`

```go
// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package flowlog

import (
	"testing"
	"time"
)

func TestClass(t *testing.T) {
	cases := []struct {
		port  uint16
		proto string
		want  string
	}{
		{53, "udp", "dns"}, {53, "tcp", "dns"},
		{80, "tcp", "http"}, {8080, "tcp", "http"},
		{443, "tcp", "https"}, {8443, "tcp", "https"},
		{5432, "tcp", "postgres"}, {6379, "tcp", "redis"},
		{50051, "tcp", "grpc"}, {4317, "tcp", "grpc"},
		{6443, "tcp", "kubernetes"}, {22, "tcp", "ssh"},
		{123, "udp", "ntp"}, {123, "UDP", "ntp"}, {123, "", "ntp"},
		{123, "tcp", ""}, // NTP hint is UDP-only
		{9999, "tcp", ""}, {0, "", ""},
	}
	for _, c := range cases {
		if got := Class(c.port, c.proto); got != c.want {
			t.Errorf("Class(%d,%q)=%q want %q", c.port, c.proto, got, c.want)
		}
	}
}

func TestParseBackend(t *testing.T) {
	for in, want := range map[string]BackendName{
		"": BackendJSON, "json": BackendJSON, "sqlite": BackendSQLite,
		"  SQLite\n": BackendSQLite, "postgres": BackendJSON,
	} {
		if got := ParseBackend(in); got != want {
			t.Errorf("ParseBackend(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBackendFromEnv(t *testing.T) {
	t.Setenv("NETRA_FLOW_BACKEND", "SQLITE")
	if got := BackendFromEnv(); got != BackendSQLite {
		t.Fatalf("got %q", got)
	}
	t.Setenv("NETRA_FLOW_BACKEND", "")
	if got := BackendFromEnv(); got != BackendJSON {
		t.Fatalf("got %q", got)
	}
}

func TestOptionsNormalize(t *testing.T) {
	got := Options{Retain: -time.Second, Max: -1, MaxBytes: 7}.Normalize()
	if got.Retain != DefaultRetain || got.Max != DefaultMax || got.MaxBytes != 7 {
		t.Fatalf("%+v", got)
	}
	kept := Options{Retain: time.Minute, Max: 3}.Normalize()
	if kept.Retain != time.Minute || kept.Max != 3 {
		t.Fatalf("explicit values overwritten: %+v", kept)
	}
}

func TestOptionsFromEnvValid(t *testing.T) {
	t.Setenv("NETRA_FLOW_RETAIN", " 2h ")
	t.Setenv("NETRA_FLOW_MAX", "50")
	t.Setenv("NETRA_FLOW_MAX_BYTES", "1048576")
	o := OptionsFromEnv()
	if o.Retain != 2*time.Hour || o.Max != 50 || o.MaxBytes != 1048576 {
		t.Fatalf("%+v", o)
	}
}

func TestOptionsFromEnvInvalidFallsBack(t *testing.T) {
	for _, bad := range [][3]string{
		{"abc", "x", "y"},
		{"0s", "0", "0"},
		{"-1h", "-5", "-1"},
	} {
		t.Setenv("NETRA_FLOW_RETAIN", bad[0])
		t.Setenv("NETRA_FLOW_MAX", bad[1])
		t.Setenv("NETRA_FLOW_MAX_BYTES", bad[2])
		o := OptionsFromEnv()
		if o.Retain != DefaultRetain || o.Max != DefaultMax || o.MaxBytes != 0 {
			t.Errorf("%v: %+v", bad, o)
		}
	}
}
```

## 6. `internal/counterfactual/memory_test.go`

```go
// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"context"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

func at(min int) Flow { return Flow{Timestamp: t0.Add(time.Duration(min) * time.Minute)} }

func timestamps(fs []Flow) []int {
	out := make([]int, len(fs))
	for i, f := range fs {
		out[i] = int(f.Timestamp.Sub(t0) / time.Minute)
	}
	return out
}

func eq(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestMemoryStoreOrdersAscending(t *testing.T) {
	m := NewMemoryStore()
	m.Add(at(3), at(1), at(2))
	if m.Len() != 3 {
		t.Fatalf("len=%d", m.Len())
	}
	got, err := m.Query(context.Background(), Query{})
	if err != nil {
		t.Fatal(err)
	}
	if !eq(timestamps(got), []int{1, 2, 3}) {
		t.Fatalf("got %v", timestamps(got))
	}
}

func TestMemoryStoreWindowStartInclusiveEndExclusive(t *testing.T) {
	m := NewMemoryStore()
	m.Add(at(0), at(1), at(2), at(3))
	got, _ := m.Query(context.Background(), Query{Start: t0.Add(time.Minute), End: t0.Add(3 * time.Minute)})
	if !eq(timestamps(got), []int{1, 2}) {
		t.Fatalf("got %v", timestamps(got))
	}
}

func TestMemoryStoreLimitAppliedAfterSort(t *testing.T) {
	m := NewMemoryStore()
	m.Add(at(5), at(4), at(1), at(3), at(2))
	got, _ := m.Query(context.Background(), Query{Limit: 2})
	if !eq(timestamps(got), []int{1, 2}) {
		t.Fatalf("limit must keep the oldest after sorting, got %v", timestamps(got))
	}
}

func TestMemoryStoreDoesNotDeduplicate(t *testing.T) {
	m := NewMemoryStore()
	m.Add(at(1), at(1))
	if m.Len() != 2 {
		t.Fatalf("len=%d", m.Len())
	}
}

// Assumes a zero WorkloadRef never has Key() == "no-such-workload".
func TestMemoryStoreWorkloadFilterExcludesNonMatching(t *testing.T) {
	m := NewMemoryStore()
	m.Add(at(1))
	got, _ := m.Query(context.Background(), Query{Workload: "no-such-workload"})
	if len(got) != 0 {
		t.Fatalf("got %d", len(got))
	}
}

func TestMemoryStoreResultIsACopy(t *testing.T) {
	m := NewMemoryStore()
	m.Add(at(1))
	got, _ := m.Query(context.Background(), Query{})
	got[0].Timestamp = t0.Add(time.Hour)
	again, _ := m.Query(context.Background(), Query{})
	if !again[0].Timestamp.Equal(t0.Add(time.Minute)) {
		t.Fatal("mutating a query result changed the store")
	}
}

func TestMemoryStoreConcurrentUse(t *testing.T) {
	m := NewMemoryStore()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(i int) { defer wg.Done(); m.Add(at(i)) }(i)
		go func() { defer wg.Done(); _, _ = m.Query(context.Background(), Query{Limit: 3}) }()
	}
	wg.Wait()
	if m.Len() != 8 {
		t.Fatalf("len=%d", m.Len())
	}
}
```

## 7. `internal/notify/format_test.go`

```go
// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package notify

import (
	"strings"
	"testing"
)

func TestTitleDefaults(t *testing.T) {
	if got := Title(Event{}); got != "[Netra][INFO] alert · " {
		t.Fatalf("got %q", got)
	}
	if got := Title(Event{Source: "alert-poller"}); got != "[Netra][INFO] alert · alert-poller" {
		t.Fatalf("subject should fall back to source, got %q", got)
	}
	got := Title(Event{Severity: "critical", Kind: "drop-spike", Subject: "n1/eth0", Source: "ignored"})
	if got != "[Netra][CRITICAL] drop-spike · n1/eth0" {
		t.Fatalf("got %q", got)
	}
}

func TestPlainFullEvent(t *testing.T) {
	ev := Event{
		Severity: "warning", Kind: "drop-spike", Subject: "n1/eth0",
		Message: "drops up", Card: "card body", Text: "text body",
		Source: "alert", Node: "n1", Fingerprint: "abc",
	}
	want := "[Netra][WARNING] drop-spike · n1/eth0\ndrops up\ncard body\nsource=alert node=n1 fingerprint=abc"
	if got := Plain(ev); got != want {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
}

func TestPlainTextFallbackAndDedup(t *testing.T) {
	// No card: text is used.
	if got := Plain(Event{Kind: "k", Message: "m", Text: "t"}); !strings.Contains(got, "\nt") {
		t.Fatalf("text missing: %q", got)
	}
	// Text equal to message is not repeated.
	if got := Plain(Event{Kind: "k", Message: "same", Text: "same"}); strings.Count(got, "same") != 1 {
		t.Fatalf("duplicated: %q", got)
	}
	// Card equal to message is skipped, so a distinct text is shown instead.
	got := Plain(Event{Kind: "k", Message: "m", Card: "m", Text: "t"})
	if strings.Count(got, "\nm") != 1 || !strings.HasSuffix(got, "\nt") {
		t.Fatalf("got %q", got)
	}
}

func TestPlainNoSourceLineWithoutSourceAndNoTrailingNewline(t *testing.T) {
	got := Plain(Event{Kind: "k", Message: "m", Node: "n1"})
	if strings.Contains(got, "source=") || strings.Contains(got, "node=") {
		t.Fatalf("node printed without source: %q", got)
	}
	if strings.HasSuffix(got, "\n") {
		t.Fatalf("trailing newline: %q", got)
	}
}

func TestSMSBodyCap(t *testing.T) {
	short := Event{Kind: "k", Message: "short"}
	if SMSBody(short) != Plain(short) {
		t.Fatal("short body must be unchanged")
	}
	long := Event{Kind: "k", Message: strings.Repeat("x", 5000)}
	got := SMSBody(long)
	if len(got) != 1500 || !strings.HasSuffix(got, "...") {
		t.Fatalf("len=%d suffix=%q", len(got), got[len(got)-3:])
	}
}
```

## 8. `web/src/lib/incidents.test.ts`

```ts
// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { describe, expect, it } from 'vitest';
import { INCIDENT_SIGNAL_LIMIT, rankSignals, visibleSignals } from './incidents';

type S = { id: string; severity: string; at: string };
const s = (id: string, severity: string, at = '2026-09-15T12:00:00Z'): S => ({ id, severity, at });
const ids = (xs: S[]) => xs.map((x) => x.id);

describe('rankSignals', () => {
  it('orders by severity, unknown last', () => {
    const out = rankSignals([s('i', 'info'), s('u', 'weird'), s('c', 'critical'), s('l', 'low'), s('h', 'high')]);
    expect(ids(out)).toEqual(['c', 'h', 'l', 'i', 'u']);
  });

  it('treats warning and medium as equal and breaks ties newest first', () => {
    const out = rankSignals([
      s('old-med', 'medium', '2026-09-15T10:00:00Z'),
      s('new-warn', 'warning', '2026-09-15T11:00:00Z'),
    ]);
    expect(ids(out)).toEqual(['new-warn', 'old-med']);
  });

  it('keeps input order for full ties, including unparsable timestamps', () => {
    const out = rankSignals([s('a', 'high', 'nope'), s('b', 'high', 'nope'), s('c', 'high', 'nope')]);
    expect(ids(out)).toEqual(['a', 'b', 'c']);
  });

  it('does not mutate its input', () => {
    const input = [s('l', 'low'), s('c', 'critical')];
    const copy = [...input];
    rankSignals(input);
    expect(input).toEqual(copy);
  });
});

describe('visibleSignals', () => {
  const many = [s('l1', 'low'), s('i1', 'info'), s('c1', 'critical'), s('l2', 'low'), s('h1', 'high'), s('m1', 'medium')];

  it('shows the worst signals first and counts the hidden rest', () => {
    const { shown, hidden } = visibleSignals(many, false);
    expect(shown).toHaveLength(INCIDENT_SIGNAL_LIMIT);
    expect(shown[0].id).toBe('c1');
    expect(ids(shown)).not.toContain('i1');
    expect(hidden).toBe(many.length - INCIDENT_SIGNAL_LIMIT);
  });

  it('shows everything when expanded', () => {
    const { shown, hidden } = visibleSignals(many, true);
    expect(shown).toHaveLength(many.length);
    expect(hidden).toBe(0);
  });

  it('hides nothing at or under the limit and honours a custom limit', () => {
    expect(visibleSignals(many.slice(0, 2), false).hidden).toBe(0);
    const { shown, hidden } = visibleSignals(many, false, 1);
    expect(ids(shown)).toEqual(['c1']);
    expect(hidden).toBe(5);
  });
});
```

---

## How to run

**Go tests (1–7)**, from the repository root:

```bash
go test -race ./internal/chatops/ ./internal/api/ -run 'SlackSignature|Principal|LocalCluster'
go test -race ./internal/l7/ ./internal/flowlog/ ./internal/counterfactual/ ./internal/notify/
go test -race ./cmd/netractl/ -run 'BPFMaps|RateDrop|IncludesRateDrops'
```

Plain `go test ./...` also picks them up. That is the CI `go` job.

**Web test (8):**

```bash
npm --prefix web run test
# or just this file:
npx --prefix web vitest run src/lib/incidents.test.ts
```

## Next candidates

These are worth testing next and use only APIs shown:

- `ai.ExplainQuestion`: question precedence and how parts are joined.
- `l7sample.sqlVerb`: comment and parenthesis skipping, and an unterminated `/*` returning `OTHER`. This depends on `upperWord`/`pick` semantics that are not shown.
- `tlsfp.ExtractClientHello`: VLAN (802.1Q) and IPv6 paths.
