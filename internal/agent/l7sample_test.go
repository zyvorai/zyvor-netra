// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/l7sample"
)

func newL7Agent() *Agent {
	return &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), l7SampleObject: "/nonexistent/netra_l7sample.o", cgroupEnabled: true, cgroupPath: "/sys/fs/cgroup"}
}

func TestL7SampleIsOffByDefaultAndReportsNothing(t *testing.T) {
	t.Setenv("NETRA_L7_SAMPLE", "")
	a := newL7Agent()
	if err := a.attachL7Sample(); err != nil || a.l7Sampler != nil {
		t.Fatalf("err=%v sampler=%v: it reads application payloads and must be opt-in", err, a.l7Sampler)
	}
	if a.readL7Sample() != nil {
		t.Fatal("an agent that never enabled it must not report an L7 summary")
	}
}

func TestAttachL7SampleModes(t *testing.T) {
	t.Run("off", func(t *testing.T) {
		t.Setenv("NETRA_L7_SAMPLE", "off")
		a := newL7Agent()
		if err := a.attachL7Sample(); err != nil || a.readL7Sample() != nil {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("auto degrades and says why", func(t *testing.T) {
		t.Setenv("NETRA_L7_SAMPLE", "auto")
		a := newL7Agent()
		if err := a.attachL7Sample(); err != nil {
			t.Fatalf("auto must not fail startup: %v", err)
		}
		got := a.readL7Sample()
		if got == nil || got.Attached || got.Unavailable == "" {
			t.Fatalf("summary = %+v, want an unattached summary carrying the reason", got)
		}
	})
	t.Run("required fails startup", func(t *testing.T) {
		t.Setenv("NETRA_L7_SAMPLE", "required")
		err := newL7Agent().attachL7Sample()
		if err == nil || !strings.Contains(err.Error(), "NETRA_L7_SAMPLE=required") {
			t.Fatalf("err = %v, want it to name the setting", err)
		}
	})
	t.Run("a bad port list is reported, not ignored", func(t *testing.T) {
		t.Setenv("NETRA_L7_SAMPLE", "auto")
		t.Setenv("NETRA_L7_SAMPLE_PORTS", "6379:notaprotocol")
		a := newL7Agent()
		_ = a.attachL7Sample()
		if got := a.readL7Sample(); got == nil || !strings.Contains(got.Unavailable, "NETRA_L7_SAMPLE_PORTS") {
			t.Fatalf("summary = %+v", got)
		}
	})
	t.Run("it needs the cgroup hierarchy", func(t *testing.T) {
		t.Setenv("NETRA_L7_SAMPLE", "required")
		a := newL7Agent()
		a.cgroupEnabled = false
		if err := a.attachL7Sample(); err == nil || !strings.Contains(err.Error(), "cgroup") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestParseL7Ports(t *testing.T) {
	got, err := parseL7Ports(defaultL7Ports)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint16]l7sample.Protocol{6379: l7sample.ProtoRedis, 5432: l7sample.ProtoPostgres, 3306: l7sample.ProtoMySQL, 9092: l7sample.ProtoKafka, 50051: l7sample.ProtoHTTP2}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for p, proto := range want {
		if got[p] != proto {
			t.Errorf("port %d = %v, want %v", p, got[p], proto)
		}
	}
	if m, err := parseL7Ports(" 8080:http1 , 9000:GRPC "); err != nil || m[8080] != l7sample.ProtoHTTP1 || m[9000] != l7sample.ProtoHTTP2 {
		t.Fatalf("spaces and case: %v %v", m, err)
	}
	for _, bad := range []string{"", "6379", "0:redis", "70000:redis", "x:redis", "6379:cobol", "6379:redis:extra:"} {
		if _, err := parseL7Ports(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	var many []string
	for i := 1; i <= 61; i++ {
		many = append(many, strings.Join([]string{itoa(1000 + i), "redis"}, ":"))
	}
	if _, err := parseL7Ports(strings.Join(many, ",")); err == nil {
		t.Error("61 ports accepted; the kernel map holds 64 and the limit is 60")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestSummarizeL7ScalesSampledCountsAndCarriesEverything(t *testing.T) {
	c := l7sample.NewCounters()
	// A server-side view: requests arrive (ingress) and replies leave (egress).
	for i := 0; i < 4; i++ {
		c.Observe(l7sample.Sample{Proto: l7sample.ProtoRedis, ToServer: true, Data: []byte("*2\r\n$3\r\nGET\r\n$1\r\nk\r\n")})
	}
	c.Observe(l7sample.Sample{Proto: l7sample.ProtoRedis, ToServer: false, Egress: true, Data: []byte("-ERR x\r\n")})
	c.Observe(l7sample.Sample{Proto: l7sample.ProtoHTTP1, ToServer: true, Data: []byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")})

	ks := l7sample.KernelStats{Eligible: 600, Emitted: 6, RateLimited: 594}
	got := summarizeL7([]string{"6379:redis"}, ks, true, c.Snapshot())
	if !got.Attached || got.Eligible != 600 || got.Emitted != 6 || got.ScaleFactor != 100 {
		t.Fatalf("kernel part = %+v", got)
	}
	if got.Seen != 6 || got.Classified != 6 || len(got.Protocols) != 2 || got.Protocols[0].Role != "served" || len(got.Hosts) != 1 || got.Hosts[0].Host != "a.example" {
		t.Fatalf("parsed part = %+v", got)
	}
	var redis = got.Protocols[1]
	if got.Protocols[0].Protocol == "redis" {
		redis = got.Protocols[0]
	}
	if redis.Requests != 4 || redis.Errors != 1 || len(redis.Ops) != 1 || redis.Ops[0].Op != "GET" || redis.Codes[0].Code != "ERR" {
		t.Fatalf("redis = %+v", redis)
	}
	// Unreadable kernel counters must not invent a scale factor.
	if bad := summarizeL7(nil, l7sample.KernelStats{}, false, c.Snapshot()); bad.ScaleFactor != 0 || bad.Seen != 6 {
		t.Fatalf("without kernel counters = %+v", bad)
	}
}
