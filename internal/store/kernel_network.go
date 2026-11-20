// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package store

import (
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type kernelNetworkSample struct {
	at             time.Time
	agentStartedAt time.Time
	counters       map[string]uint64
	softnetDropped uint64
	softnetSqueeze uint64
	interfaces     map[string]models.InterfaceStackStat
	qdiscDrops     map[string]uint64
}

const (
	kernelNetworkSampleMinInterval = 10 * time.Second
	kernelNetworkSampleMaxAge      = 2 * time.Hour
	kernelNetworkSampleMaxEntries  = 900
)

func sampleKernelNetwork(r models.AgentReport) kernelNetworkSample {
	at := r.ObservedAt.UTC()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	x := kernelNetworkSample{
		at: at, agentStartedAt: r.AgentStartedAt.UTC(), counters: map[string]uint64{},
		softnetDropped: r.Stack.SoftnetDropped, softnetSqueeze: r.Stack.SoftnetTimeSqueeze,
		interfaces: map[string]models.InterfaceStackStat{}, qdiscDrops: map[string]uint64{},
	}
	for _, c := range r.KernelNetwork.Counters {
		x.counters[c.Name] = c.Value
	}
	for _, it := range r.Stack.Interfaces {
		x.interfaces[it.Name] = it
	}
	for _, q := range r.QdiscStats {
		x.qdiscDrops[q.Interface+"|"+q.Kind+"|"+q.Handle] = q.Drops
	}
	return x
}

func (s *Store) appendKernelNetworkSampleLocked(r models.AgentReport) {
	if s.kernelNetworkSamples == nil {
		s.kernelNetworkSamples = map[string][]kernelNetworkSample{}
	}
	sample := sampleKernelNetwork(r)
	items := s.kernelNetworkSamples[r.Node]
	if len(items) > 0 {
		last := items[len(items)-1]
		sameProcess := sample.agentStartedAt.IsZero() || last.agentStartedAt.IsZero() || sample.agentStartedAt.Equal(last.agentStartedAt)
		if sameProcess && sample.at.Sub(last.at) < kernelNetworkSampleMinInterval {
			return
		}
	}
	items = append(items, sample)
	cutoff := sample.at.Add(-kernelNetworkSampleMaxAge)
	first := 0
	for first < len(items) && items[first].at.Before(cutoff) {
		first++
	}
	if first > 0 {
		items = append([]kernelNetworkSample(nil), items[first:]...)
	}
	if len(items) > kernelNetworkSampleMaxEntries {
		items = append([]kernelNetworkSample(nil), items[len(items)-kernelNetworkSampleMaxEntries:]...)
	}
	s.kernelNetworkSamples[r.Node] = items
}

// KernelNetworkWindows returns delta/rate evidence over a bounded window.
// Counter resets are excluded and reported; they are never converted into a
// huge unsigned delta or silently treated as evidence of a healthy interval.
func (s *Store) KernelNetworkWindows(window time.Duration) []models.KernelNetworkWindow {
	if window < 30*time.Second {
		window = 30 * time.Second
	}
	if window > 2*time.Hour {
		window = 2 * time.Hour
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.KernelNetworkWindow, 0, len(s.kernelNetworkSamples))
	for node, samples := range s.kernelNetworkSamples {
		w := models.KernelNetworkWindow{Node: node, Warming: true}
		if len(samples) < 2 {
			out = append(out, w)
			continue
		}
		end := samples[len(samples)-1]
		startIdx := len(samples) - 1
		threshold := end.at.Add(-window)
		for i := len(samples) - 2; i >= 0; i-- {
			if !end.agentStartedAt.IsZero() && !samples[i].agentStartedAt.IsZero() && !end.agentStartedAt.Equal(samples[i].agentStartedAt) {
				w.ResetDetected = true
				w.ResetSignals = append(w.ResetSignals, "agent-restart")
				break
			}
			startIdx = i
			if !samples[i].at.After(threshold) {
				break
			}
		}
		if startIdx == len(samples)-1 {
			// w already carries any ResetDetected the backward search above
			// set on it — no valid same-process start sample exists inside
			// the window, so there is nothing for windowBetween to compute.
			out = append(out, w)
			continue
		}
		out = append(out, windowBetween(node, samples[startIdx], end))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// windowBetween computes a KernelNetworkWindow's delta/rate fields for one
// pair of stored samples. KernelNetworkWindows uses it once, for the
// (start, end) pair its backward search selects for the requested window
// duration; KernelNetworkSparkline reuses it unchanged across several
// adjacent sample pairs to build a short trend line — same evidence, same
// reset-safety, not a second implementation of the delta logic.
func windowBetween(node string, start, end kernelNetworkSample) models.KernelNetworkWindow {
	w := models.KernelNetworkWindow{Node: node, Warming: true}
	if !end.agentStartedAt.IsZero() && !start.agentStartedAt.IsZero() && !end.agentStartedAt.Equal(start.agentStartedAt) {
		w.ResetDetected = true
		w.ResetSignals = append(w.ResetSignals, "agent-restart")
		return w
	}
	seconds := end.at.Sub(start.at).Seconds()
	if seconds <= 0 {
		return w
	}
	w.StartAt, w.EndAt, w.Seconds, w.Warming = start.at, end.at, seconds, false
	for name, endValue := range end.counters {
		startValue, ok := start.counters[name]
		if !ok {
			continue
		}
		delta, ok := deltaU64(startValue, endValue)
		if !ok {
			w.ResetDetected = true
			w.ResetSignals = append(w.ResetSignals, name)
			continue
		}
		w.Counters = append(w.Counters, models.KernelNetworkCounterDelta{Name: name, Delta: delta, PerSecond: float64(delta) / seconds})
	}
	w.SoftnetDropped = windowDelta(&w, "softnet_dropped", start.softnetDropped, end.softnetDropped)
	w.SoftnetTimeSqueeze = windowDelta(&w, "softnet_time_squeeze", start.softnetSqueeze, end.softnetSqueeze)
	for name, endValue := range end.interfaces {
		startValue, ok := start.interfaces[name]
		if !ok {
			continue
		}
		w.RXDropped += windowDelta(&w, "interface:"+name+":rx_dropped", startValue.RXDropped, endValue.RXDropped)
		w.TXDropped += windowDelta(&w, "interface:"+name+":tx_dropped", startValue.TXDropped, endValue.TXDropped)
		w.RXMissed += windowDelta(&w, "interface:"+name+":rx_missed", startValue.RXMissed, endValue.RXMissed)
	}
	for key, endValue := range end.qdiscDrops {
		startValue, ok := start.qdiscDrops[key]
		if !ok {
			continue
		}
		w.QdiscDrops += windowDelta(&w, "qdisc:"+key, startValue, endValue)
	}
	w.SoftnetDroppedRate = float64(w.SoftnetDropped) / seconds
	w.SoftnetSqueezeRate = float64(w.SoftnetTimeSqueeze) / seconds
	w.RXDroppedRate = float64(w.RXDropped) / seconds
	w.TXDroppedRate = float64(w.TXDropped) / seconds
	w.RXMissedRate = float64(w.RXMissed) / seconds
	w.QdiscDropsRate = float64(w.QdiscDrops) / seconds
	sort.Slice(w.Counters, func(i, j int) bool { return w.Counters[i].Name < w.Counters[j].Name })
	sort.Strings(w.ResetSignals)
	return w
}

// KernelNetworkSparkline returns up to maxPoints consecutive per-node delta
// windows (oldest first), reusing windowBetween across each adjacent pair
// of stored samples — not a general time-series API, just enough for a
// short trend line. Bounded by the same 2h/900-sample store this package
// already keeps and by maxPoints, capped at 60 (~the last 20 minutes at
// the store's 10s minimum sample interval).
func (s *Store) KernelNetworkSparkline(node string, maxPoints int) []models.KernelNetworkWindow {
	const maxSparklinePoints = 60
	if maxPoints <= 0 {
		maxPoints = maxSparklinePoints
	}
	// Both branches rebind maxPoints so the make below is capped at
	// maxSparklinePoints instead of the caller-supplied size.
	if maxPoints > maxSparklinePoints {
		maxPoints = maxSparklinePoints
	} else {
		bounded := maxPoints
		maxPoints = bounded
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	samples := s.kernelNetworkSamples[node]
	if len(samples) < 2 {
		return nil
	}
	start := 0
	if len(samples)-1-maxPoints > start {
		start = len(samples) - 1 - maxPoints
	}
	out := make([]models.KernelNetworkWindow, 0, maxPoints)
	for i := start + 1; i < len(samples); i++ {
		out = append(out, windowBetween(node, samples[i-1], samples[i]))
	}
	return out
}

func windowDelta(w *models.KernelNetworkWindow, name string, start, end uint64) uint64 {
	delta, ok := deltaU64(start, end)
	if !ok {
		w.ResetDetected = true
		w.ResetSignals = append(w.ResetSignals, name)
		return 0
	}
	return delta
}
