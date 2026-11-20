// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/listenq"
)

func newListenQAgent() *Agent {
	return &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestListenQueuesOffMeansNoReport(t *testing.T) {
	t.Setenv("NETRA_LISTEN_QUEUES", "off")
	a := newListenQAgent()
	a.attachListenQueues()
	if a.listenQ != nil || a.readListenQueues() != nil {
		t.Fatal("NETRA_LISTEN_QUEUES=off must produce no sampler and no report")
	}
}

func TestListenQueuesDefaultIsOn(t *testing.T) {
	t.Setenv("NETRA_LISTEN_QUEUES", "")
	a := newListenQAgent()
	a.attachListenQueues()
	if a.listenQ == nil {
		t.Fatal("an unset NETRA_LISTEN_QUEUES must behave as auto (on)")
	}
}

func TestReadListenQueuesConvertsTheSnapshot(t *testing.T) {
	a := newListenQAgent()
	a.listenQ = &listenq.Sampler{Dump: func() ([]listenq.Listener, error) {
		return []listenq.Listener{
			{Family: "ipv4", Addr: "0.0.0.0", Port: 8080, Queue: 2, Max: 1, SynRecv: 3},
			{Family: "ipv4", Addr: "0.0.0.0", Port: 22, Queue: 0, Max: 128},
		}, nil
	}}
	got := a.readListenQueues()
	if got == nil || got.Unavailable != "" || got.Listeners != 2 || got.Full != 1 || got.SynRecv != 3 {
		t.Fatalf("summary = %+v", got)
	}
	if len(got.Top) != 1 || got.Top[0].Port != 8080 || got.Top[0].Queue != 2 || got.Top[0].Max != 1 || got.Top[0].PeakPct != 100 {
		t.Fatalf("top = %+v, want only the listener under pressure", got.Top)
	}
	if got.Buckets["full"] != 1 || got.Buckets["empty"] != 1 {
		t.Fatalf("buckets = %v", got.Buckets)
	}
}

func TestReadListenQueuesReportsWhyItCannotReadAndRecovers(t *testing.T) {
	fail := true
	a := newListenQAgent()
	a.listenQ = &listenq.Sampler{Dump: func() ([]listenq.Listener, error) {
		if fail {
			return nil, errors.New(strings.Repeat("netlink refused ", 100))
		}
		return nil, nil
	}}
	got := a.readListenQueues()
	if got == nil || got.Unavailable == "" || len(got.Unavailable) > maxWhy {
		t.Fatalf("a failing read must be reported as unavailable with a bounded reason: %+v", got)
	}
	if !a.listenQWarned {
		t.Error("the first failure should be logged")
	}
	fail = false
	if got := a.readListenQueues(); got == nil || got.Unavailable != "" {
		t.Fatalf("after recovery the summary must be normal: %+v", got)
	}
	if a.listenQWarned {
		t.Error("recovery must re-arm the one-line warning")
	}
}
