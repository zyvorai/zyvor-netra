// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/l7sample"
	"github.com/zyvorai/netra/internal/sslprobe"
)

func newTLSAgent() *Agent {
	return &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), sslObject: "/nonexistent/netra_ssl.o"}
}

func TestTLSSamplingIsOffByDefaultAndReportsNothing(t *testing.T) {
	t.Setenv("NETRA_TLS_UPROBES", "")
	a := newTLSAgent()
	if err := a.attachTLSUprobes(); err != nil || a.sslProber != nil {
		t.Fatalf("err=%v prober=%v: it observes plaintext and must be opt-in", err, a.sslProber)
	}
	if a.readTLSSample() != nil {
		t.Fatal("an agent that never enabled it must not report a TLS summary")
	}
}

func TestAttachTLSUprobesModes(t *testing.T) {
	t.Run("off", func(t *testing.T) {
		t.Setenv("NETRA_TLS_UPROBES", "off")
		a := newTLSAgent()
		if err := a.attachTLSUprobes(); err != nil || a.readTLSSample() != nil {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("auto degrades and says why", func(t *testing.T) {
		t.Setenv("NETRA_TLS_UPROBES", "auto")
		a := newTLSAgent()
		if err := a.attachTLSUprobes(); err != nil {
			t.Fatalf("auto must not fail startup: %v", err)
		}
		got := a.readTLSSample()
		if got == nil || got.Attached || got.Unavailable == "" {
			t.Fatalf("summary = %+v, want an unattached summary carrying the reason", got)
		}
	})
	t.Run("the reason is bounded", func(t *testing.T) {
		a := newTLSAgent()
		a.sslWhy = strings.Repeat("x", 5000)
		if got := a.readTLSSample(); len(got.Unavailable) != maxWhy {
			t.Fatalf("reason is %d bytes, want %d", len(got.Unavailable), maxWhy)
		}
	})
	t.Run("required fails startup", func(t *testing.T) {
		t.Setenv("NETRA_TLS_UPROBES", "required")
		err := newTLSAgent().attachTLSUprobes()
		if err == nil || !strings.Contains(err.Error(), "NETRA_TLS_UPROBES=required") {
			t.Fatalf("err = %v, want it to name the setting", err)
		}
	})
}

func TestSummarizeTLSCarriesTheAllowlistLibrariesAndScale(t *testing.T) {
	c := l7sample.NewCounters()
	req := sslprobe.Event{Write: true, Data: []byte("GET /secret-path?x=SECRET HTTP/1.1\r\nHost: shop.example\r\n\r\n")}
	resp := sslprobe.Event{Write: false, Data: []byte("HTTP/1.1 503 Service Unavailable\r\n\r\n")}
	for _, e := range []sslprobe.Event{req, req, resp} {
		o, role, ok := sslprobe.Classify(e.Write, e.Data)
		c.ObserveObs(o, ok, role)
	}
	c.ObserveObs(l7sample.Obs{}, false, "") // an unclassifiable fragment

	ks := sslprobe.KernelStats{Eligible: 900, Emitted: 9, RateLimited: 891, CommFiltered: 3}
	got := summarizeTLS([]string{"/usr/lib/libssl.so.3"}, []string{"nginx"}, ks, true, c.Snapshot())
	if !got.Attached || got.Eligible != 900 || got.Emitted != 9 || got.ScaleFactor != 100 || got.CommFiltered != 3 {
		t.Fatalf("kernel part = %+v", got)
	}
	if len(got.Libraries) != 1 || len(got.Comms) != 1 || got.Comms[0] != "nginx" {
		t.Fatalf("libraries/comms = %+v %+v", got.Libraries, got.Comms)
	}
	if got.Seen != 4 || got.Classified != 3 || len(got.Protocols) != 1 || got.Protocols[0].Protocol != "http1" || got.Protocols[0].Role != "issued" {
		t.Fatalf("parsed part = %+v", got)
	}
	if len(got.Hosts) != 1 || got.Hosts[0].Host != "shop.example" {
		t.Fatalf("hosts = %+v", got.Hosts)
	}
	if s := strings.ToLower(strings.Join([]string{got.Protocols[0].Ops[0].Op, got.Hosts[0].Host}, " ")); strings.Contains(s, "secret") {
		t.Fatalf("summary carries request text: %s", s)
	}
	if bad := summarizeTLS(nil, nil, sslprobe.KernelStats{}, false, c.Snapshot()); bad.ScaleFactor != 0 || bad.Seen != 4 {
		t.Fatalf("without kernel counters = %+v", bad)
	}
}
