// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/bpfattach"
)

type fakeAttachKernel struct{ calls int }

func (f *fakeAttachKernel) Links() ([]bpfattach.LinkInfo, error) {
	f.calls++
	return []bpfattach.LinkInfo{{Index: 2, Name: "eth0", XDPID: 5}}, nil
}
func (f *fakeAttachKernel) TCX(int, bool) ([]uint32, bool, error)      { return nil, true, nil }
func (f *fakeAttachKernel) TC(int, bool) ([]bpfattach.TCFilter, error) { return nil, nil }
func (f *fakeAttachKernel) ProgramName(uint32) (string, error)         { return "netra_xdp_ingre", nil }

func TestBPFAttachOffMeansNoReport(t *testing.T) {
	t.Setenv("NETRA_BPF_ATTACH", "off")
	a := newListenQAgent()
	a.startBPFAttach()
	rep, commit := a.readBPFAttach(time.Now())
	if a.bpfSource != nil || rep != nil {
		t.Fatal("NETRA_BPF_ATTACH=off must produce no source and no report")
	}
	commit()
}

func TestBPFAttachDefaultIsOn(t *testing.T) {
	t.Setenv("NETRA_BPF_ATTACH", "")
	a := newListenQAgent()
	a.startBPFAttach()
	if a.bpfSource == nil {
		t.Fatal("an unset NETRA_BPF_ATTACH must behave as auto (on)")
	}
}

func TestBPFAttachSendsTheListThenOnlyASummaryUntilItChangesOrIsDue(t *testing.T) {
	k := &fakeAttachKernel{}
	a := newListenQAgent()
	a.bpfSource = k
	t0 := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

	rep, commit := a.readBPFAttach(t0)
	if rep.Unchanged || len(rep.Interfaces) != 1 {
		t.Fatalf("the first report must carry the list: %+v", rep)
	}
	// The POST failed: no commit, so the next tick sends the list again.
	if again, _ := a.readBPFAttach(t0.Add(3 * time.Second)); again.Unchanged {
		t.Fatal("an undelivered list must be resent, not summarised")
	}
	commit()
	stub, _ := a.readBPFAttach(t0.Add(6 * time.Second))
	if !stub.Unchanged || stub.Interfaces != nil || stub.Hash != rep.Hash {
		t.Fatalf("after delivery only a summary is due: %+v", stub)
	}
	if k.calls != 1 {
		t.Fatalf("the kernel was asked %d times inside %s, want 1", k.calls, bpfAttachEvery)
	}
	// Past the refresh interval the list is sent again (a restarted controller recovers).
	late, _ := a.readBPFAttach(t0.Add(bpfAttachRefresh + time.Second))
	if late.Unchanged || len(late.Interfaces) != 1 {
		t.Fatalf("the list must be refreshed periodically: %+v", late)
	}
	if k.calls < 2 {
		t.Fatal("the kernel was never re-read after the interval")
	}
}
