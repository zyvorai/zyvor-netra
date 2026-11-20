// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package agent

import (
	"context"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/netlinkwatch"
	"github.com/zyvorai/netra/internal/rtnlactor"
)

const (
	// rtnlAttributionGrace holds a change back from its report until the request
	// record that explains it has had time to arrive (the two are read from the
	// kernel independently).
	rtnlAttributionGrace = 300 * time.Millisecond
	// rtnlDropPoll is how often the kernel's count of unbuffered requests is read.
	rtnlDropPoll = 5 * time.Second
)

// actorTarget is what attribution attaches to: the netlink recorder.
type actorTarget interface {
	SetAttributor(a netlinkwatch.Attributor, grace time.Duration)
	SetActorUnavailable(why string)
}

// startRTNLActor loads the fentry that names the process behind each network
// change (bpf/netra_rtnl.c) and attaches attribution to the netlink recorder.
// NETRA_RTNL_ACTOR=auto (default) or off. It needs kernel BTF and fentry support;
// where the kernel cannot run it the report says so and the recorder carries on
// unattributed: nothing about recording depends on it. Requires the recorder, since
// there is nothing to attribute otherwise.
func (a *Agent) startRTNLActor(ctx context.Context, target actorTarget) {
	if strings.ToLower(env("NETRA_RTNL_ACTOR", "auto")) == "off" {
		a.log.Info("netlink change attribution skipped by NETRA_RTNL_ACTOR=off")
		return
	}
	s, err := rtnlactor.Load(rtnlactor.Options{
		ObjectPath: env("NETRA_BPF_RTNL_OBJECT", "/opt/netra/bpf/netra_rtnl.o"), Log: a.log,
	})
	if err != nil {
		why := err.Error()
		if len(why) > maxWhy {
			why = why[:maxWhy]
		}
		target.SetActorUnavailable(why)
		a.log.Warn("netlink change attribution unavailable; changes are recorded without a requester", "error", err)
		return
	}
	j := rtnlactor.NewJoiner(a.rtnlResolve, rtnlactor.SelfNetNS())
	a.rtnlSensor = s
	target.SetAttributor(j, rtnlAttributionGrace)
	go s.Run(ctx, j.Add)
	go func() {
		t := time.NewTicker(rtnlDropPoll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := s.Dropped(); err == nil {
					j.NoteDropped(n, time.Now())
				}
			}
		}
	}()
	a.log.Info("netlink change attribution attached", "hook", "fentry:rtnetlink_rcv_msg")
}

// rtnlResolve names the pod a requester's cgroup belongs to, using the workload
// identities the agent already keeps; a host process has none.
func (a *Agent) rtnlResolve(cgroupID uint64) (namespace, pod, workload string, ok bool) {
	w, found := a.workloadIdentity(cgroupID)
	if !found {
		return "", "", "", false
	}
	return w.Namespace, w.Pod, w.WorkloadName, true
}
