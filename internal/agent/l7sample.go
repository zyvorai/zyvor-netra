// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package agent

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/l7sample"
	"github.com/zyvorai/netra/internal/models"
)

// defaultL7Ports are the well-known service ports observed when
// NETRA_L7_SAMPLE_PORTS is not set. 50051 is the conventional gRPC port; gRPC
// services on other ports are added through the setting.
const defaultL7Ports = "6379:redis,5432:postgres,3306:mysql,9092:kafka,50051:grpc"

// parseL7Ports parses "port:protocol,port:protocol". It rejects a malformed or
// unknown entry rather than silently sampling less than was asked for.
func parseL7Ports(spec string) (map[uint16]l7sample.Protocol, error) {
	out := map[uint16]l7sample.Protocol{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ps, name, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("%q: want port:protocol", part)
		}
		port, err := strconv.Atoi(strings.TrimSpace(ps))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("%q: %q is not a port", part, ps)
		}
		proto := l7sample.ProtocolByName(strings.ToLower(strings.TrimSpace(name)))
		if proto == l7sample.ProtoUnknown {
			return nil, fmt.Errorf("%q: unknown protocol %q (redis, postgres, mysql, kafka, http2, grpc, http1)", part, name)
		}
		out[uint16(port)] = proto
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports configured")
	}
	if len(out) > 60 {
		return nil, fmt.Errorf("%d ports configured; the limit is 60", len(out))
	}
	return out, nil
}

// attachL7Sample starts the sampled application-protocol observer. It reads
// application payload bytes (in memory, briefly, never exported), so it is OFF by
// default: NETRA_L7_SAMPLE=auto|required|off, default off. auto degrades with the
// reason reported; required fails startup.
func (a *Agent) attachL7Sample() error {
	mode := strings.ToLower(env("NETRA_L7_SAMPLE", "off"))
	if mode == "off" || mode == "" {
		return nil
	}
	fail := func(why error) error {
		if mode == "required" {
			return fmt.Errorf("L7 protocol sampling (NETRA_L7_SAMPLE=required): %w", why)
		}
		a.l7SampleWhy = why.Error()
		a.log.Warn("L7 protocol sampling unavailable; continuing without it", "error", why)
		return nil
	}
	if !a.cgroupEnabled {
		return fail(fmt.Errorf("it attaches to the cgroup hierarchy, which is disabled"))
	}
	ports, err := parseL7Ports(env("NETRA_L7_SAMPLE_PORTS", defaultL7Ports))
	if err != nil {
		return fail(fmt.Errorf("NETRA_L7_SAMPLE_PORTS: %w", err))
	}
	gap := envDuration("NETRA_L7_SAMPLE_GAP", 100*time.Millisecond)
	s, err := l7sample.Load(l7sample.Options{ObjectPath: a.l7SampleObject, CgroupPath: a.cgroupPath, Ports: ports, MinGap: gap, Log: a.log})
	if err != nil {
		return fail(err)
	}
	a.l7Sampler = s
	a.l7Counters = l7sample.NewCounters()
	a.l7SamplePorts = a.l7SamplePorts[:0]
	for p, proto := range ports {
		a.l7SamplePorts = append(a.l7SamplePorts, fmt.Sprintf("%d:%s", p, proto))
	}
	sort.Strings(a.l7SamplePorts)
	a.hooks = append(a.hooks, "l7sample-cgroup-egress", "l7sample-cgroup-ingress")
	a.markAttached("netra_l7s_egress")
	a.markAttached("netra_l7s_ingress")
	a.log.Info("L7 protocol sampling attached (payload is parsed in the agent and never exported)", "ports", a.l7SamplePorts, "minGap", gap.String())
	return nil
}

// readL7Sample returns nil when sampling is off, and an Unavailable summary when
// it tried and could not start.
func (a *Agent) readL7Sample() *models.L7SampleSummary {
	if a.l7Sampler == nil {
		if a.l7SampleWhy == "" {
			return nil
		}
		why := a.l7SampleWhy
		if len(why) > maxWhy {
			why = why[:maxWhy]
		}
		return &models.L7SampleSummary{Unavailable: why}
	}
	ks, err := a.l7Sampler.KernelStats()
	if err != nil {
		a.log.Warn("read L7 sampler counters", "error", err)
	}
	return summarizeL7(a.l7SamplePorts, ks, err == nil, a.l7Counters.Snapshot())
}

// summarizeL7 builds the report from the kernel counters and the parsed counts.
// ksOK is false when the kernel counters could not be read (the counts are still
// reported, without a scale factor).
func summarizeL7(ports []string, ks l7sample.KernelStats, ksOK bool, snap l7sample.Snapshot) *models.L7SampleSummary {
	out := &models.L7SampleSummary{Attached: true, Ports: ports}
	if ksOK {
		out.Eligible, out.Emitted, out.RateLimited, out.RingbufFull, out.LoadFail = ks.Eligible, ks.Emitted, ks.RateLimited, ks.RingbufFull, ks.LoadFail
		if ks.Emitted > 0 {
			out.ScaleFactor = float64(ks.Eligible) / float64(ks.Emitted)
		}
	}
	out.Seen, out.Classified, out.Overflow = snap.Seen, snap.Classified, snap.Overflow
	for _, p := range snap.Protocols {
		mp := models.L7SampleProtocol{Protocol: p.Protocol, Role: p.Role, Requests: p.Requests, Responses: p.Responses, Errors: p.Errors, Undecodable: p.Undecodable, GRPC: p.GRPC}
		for _, o := range p.Ops {
			mp.Ops = append(mp.Ops, models.L7SampleOp{Op: o.Op, Count: o.Count})
		}
		for _, c := range p.Codes {
			mp.Codes = append(mp.Codes, models.L7SampleCode{Code: c.Code, Status: c.Status, Count: c.Count})
		}
		out.Protocols = append(out.Protocols, mp)
	}
	for _, h := range snap.Hosts {
		out.Hosts = append(out.Hosts, models.L7SampleHost{Role: h.Role, Host: h.Host, Op: h.Op, Count: h.Count})
	}
	return out
}
