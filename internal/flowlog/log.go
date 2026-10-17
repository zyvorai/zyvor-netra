// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package flowlog keeps a bounded, in-memory history of observed flows.
// Records are counter deltas (pod, peer, port, protocol, bytes, drops).
// No payloads, no argv, no destination labels for Prometheus.
package flowlog

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

const (
	// DefaultRetain is how long flow deltas stay on disk and in memory.
	DefaultRetain = 7 * 24 * time.Hour
	DefaultMax    = 100000
)

// Record is one observed delta, not a cumulative counter and not a packet.
type Record struct {
	ObservedAt   time.Time `json:"observedAt"`
	Node         string    `json:"node,omitempty"`
	Namespace    string    `json:"namespace,omitempty"`
	Pod          string    `json:"pod,omitempty"`
	WorkloadKind string    `json:"workloadKind,omitempty"`
	WorkloadName string    `json:"workloadName,omitempty"`
	Peer         string    `json:"peer"`
	Port         uint16    `json:"port"`
	Protocol     string    `json:"protocol,omitempty"`
	Direction    string    `json:"direction,omitempty"`
	AppProtocol  string    `json:"appProtocol,omitempty"`
	Packets      uint64    `json:"packets,omitempty"`
	Bytes        uint64    `json:"bytes,omitempty"`
	Blocked      uint64    `json:"blocked,omitempty"`
	Retrans      uint64    `json:"retransmissions,omitempty"`
	RTOs         uint64    `json:"rtos,omitempty"`
	SRTTUS       uint64    `json:"srttUs,omitempty"`
	PID          uint32    `json:"pid,omitempty"`
	Comm         string    `json:"comm,omitempty"`
	// DNSName / TLSSNI are best-effort joins from the same agent report
	// (DNS events and TLS SNI stats). Empty when the report had no name for
	// that peer — never invented. Enables historical deny-preview for dns/sni.
	DNSName string `json:"dnsName,omitempty"`
	TLSSNI  string `json:"tlsSni,omitempty"`
}

// Query filters history. Zero time means no bound on that side.
type Query struct {
	Since, Until time.Time
	Node         string
	Namespace    string
	Pod          string
	Peer         string
	Protocol     string
	AppProtocol  string
	Limit        int
}

// Result is GET /api/v1/flows/history.
type Result struct {
	Records     []Record `json:"records"`
	Matched     int      `json:"matched"`
	Truncated   bool     `json:"truncated,omitempty"`
	Limitations []string `json:"limitations"`
}

// Limitations is the honest contract for every history response.
func Limitations() []string {
	return []string{
		"Flow deltas are kept for 7 days, capped at 100000 records, in a sidecar file next to the controller state. Not a column store. The first sample after a restart is a new baseline.",
		"First sample of a flow sets a baseline and is not emitted, so rates start on the second report.",
		"App protocol is a well-known-port hint, not a payload decode. HTTP/2 and HTTP/3 are not decoded. Cleartext HTTP/1 status is counted only when the status line starts the packet.",
		"Process comm and pid are copied from TCP health when the peer and port match. No argv or cmdline.",
		"DNS qname and TLS SNI are best-effort joins from the same agent report when present; empty means unobserved, never invented.",
		"No packet payloads. Kernel kfree_skb drops stay reason counts. Application journal is not collected.",
	}
}

type prevStat struct {
	packets, bytes, blocked, retrans, rtos uint64
}

// Log is safe for concurrent ingest and query.
type Log struct {
	mu       sync.Mutex
	retain   time.Duration
	max      int
	recs     []Record
	prev     map[string]prevStat
	dirty    bool
	gen      uint64
	lastSave time.Time
	saveMu   sync.Mutex
}

func New() *Log { return NewLimited(DefaultRetain, DefaultMax) }

func NewLimited(retain time.Duration, max int) *Log {
	if retain <= 0 {
		retain = DefaultRetain
	}
	if max <= 0 {
		max = DefaultMax
	}
	return &Log{retain: retain, max: max, prev: map[string]prevStat{}}
}

func (l *Log) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recs)
}

// Ingest turns one agent report into deltas. The first observation of a
// key is stored as a baseline and produces no record.
func (l *Log) Ingest(now time.Time, r models.AgentReport) {
	if l == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	tcp := indexTCP(r.TCPHealth)
	comms := indexComm(r.ProcessMeta)
	dnsByPeer := indexDNSNames(r.Events)
	sniByWorkload := indexSNI(r.TLSMetadata)

	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	for _, st := range r.Stats {
		if st.DestinationIP == "" {
			continue
		}
		key := flowKey(r.Node, st)
		cur := prevStat{packets: st.Packets, bytes: st.Bytes, blocked: st.Blocked}
		join, ok := tcp[st.DestinationIP+"|"+strconv.Itoa(int(st.Port))]
		if ok {
			cur.retrans = join.retrans
			cur.rtos = join.rtos
		}
		old, seen := l.prev[key]
		l.prev[key] = cur
		if !seen {
			continue
		}
		rec := Record{
			ObservedAt:   now,
			Node:         r.Node,
			Namespace:    st.Namespace,
			Pod:          st.Pod,
			WorkloadKind: st.WorkloadKind,
			WorkloadName: st.WorkloadName,
			Peer:         st.DestinationIP,
			Port:         st.Port,
			Protocol:     strings.ToLower(st.Protocol),
			Direction:    st.Direction,
			AppProtocol:  Class(st.Port, st.Protocol),
			SRTTUS:       join.srtt,
		}
		rec.Packets = delta(st.Packets, old.packets)
		rec.Bytes = delta(st.Bytes, old.bytes)
		rec.Blocked = delta(st.Blocked, old.blocked)
		rec.Retrans = delta(cur.retrans, old.retrans)
		rec.RTOs = delta(cur.rtos, old.rtos)
		if ok && !join.stale && join.pid != 0 {
			rec.PID = uint32(join.pid)
			rec.Comm = join.comm
		}
		if rec.Comm == "" && rec.PID != 0 {
			rec.Comm = comms[rec.PID]
		}
		rec.DNSName = dnsByPeer[st.DestinationIP]
		rec.TLSSNI = sniByWorkload[st.Namespace+"|"+st.Pod]
		if rec.TLSSNI == "" {
			rec.TLSSNI = sniByWorkload["|"+st.Pod]
		}
		if rec.Packets == 0 && rec.Bytes == 0 && rec.Blocked == 0 && rec.Retrans == 0 && rec.RTOs == 0 {
			continue
		}
		l.recs = append(l.recs, rec)
		l.dirty = true
		l.gen++
	}
	l.pruneLocked(now)
	if len(l.prev) > l.max*2 {
		l.prev = map[string]prevStat{}
	}
}

func delta(cur, old uint64) uint64 {
	if cur < old {
		return cur
	}
	return cur - old
}

func flowKey(node string, st models.DestinationStat) string {
	return strings.Join([]string{
		node,
		st.Namespace,
		st.Pod,
		st.DestinationIP,
		strconv.Itoa(int(st.Port)),
		strings.ToLower(st.Protocol),
		st.Direction,
	}, "|")
}

type tcpJoin struct {
	pid, retrans, rtos, srtt uint64
	comm                     string
	stale                    bool
}

func indexTCP(stats []models.TCPHealthStat) map[string]tcpJoin {
	out := make(map[string]tcpJoin, len(stats))
	for _, t := range stats {
		j := tcpJoin{
			pid: uint64(t.PID), comm: t.Comm, stale: t.OwnershipStale,
			retrans: t.Retransmissions, rtos: t.RTOs, srtt: t.SRTTUS,
		}
		if t.RemoteIP != "" {
			out[t.RemoteIP+"|"+strconv.Itoa(int(t.RemotePort))] = j
		}
	}
	return out
}

func indexComm(meta []models.ProcessMetaStat) map[uint32]string {
	out := make(map[uint32]string, len(meta))
	for _, m := range meta {
		if m.PID != 0 && m.Comm != "" {
			out[m.PID] = m.Comm
		}
	}
	return out
}

// indexDNSNames maps destination IP → most recent DNS qname from sampled events.
func indexDNSNames(events []models.FastPathEvent) map[string]string {
	out := make(map[string]string)
	for _, e := range events {
		if e.DNSQuery == "" || e.DestinationIP == "" {
			continue
		}
		out[e.DestinationIP] = e.DNSQuery
	}
	return out
}

// indexSNI maps "namespace|pod" → SNI from TLS metadata (first non-empty wins).
func indexSNI(tls []models.TLSMetadataStat) map[string]string {
	out := make(map[string]string, len(tls))
	for _, t := range tls {
		if t.SNI == "" {
			continue
		}
		key := t.Namespace + "|" + t.Pod
		if _, ok := out[key]; !ok {
			out[key] = t.SNI
		}
		if t.Pod != "" {
			loose := "|" + t.Pod
			if _, ok := out[loose]; !ok {
				out[loose] = t.SNI
			}
		}
	}
	return out
}

func (l *Log) pruneLocked(now time.Time) {
	cut := now.Add(-l.retain)
	i := 0
	for i < len(l.recs) && l.recs[i].ObservedAt.Before(cut) {
		i++
	}
	if i > 0 {
		l.recs = append([]Record(nil), l.recs[i:]...)
	}
	if len(l.recs) > l.max {
		l.recs = append([]Record(nil), l.recs[len(l.recs)-l.max:]...)
	}
}

// Query returns newest-first records that match.
func (l *Log) Query(q Query) Result {
	res := Result{Records: []Record{}, Limitations: Limitations()}
	if l == nil {
		return res
	}
	if q.Limit <= 0 {
		q.Limit = 200
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(time.Now().UTC())
	for i := len(l.recs) - 1; i >= 0; i-- {
		rec := l.recs[i]
		if !q.Since.IsZero() && rec.ObservedAt.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && rec.ObservedAt.After(q.Until) {
			continue
		}
		if q.Node != "" && rec.Node != q.Node {
			continue
		}
		if q.Namespace != "" && rec.Namespace != q.Namespace {
			continue
		}
		if q.Pod != "" && rec.Pod != q.Pod {
			continue
		}
		if q.Peer != "" && rec.Peer != q.Peer {
			continue
		}
		if q.Protocol != "" && !strings.EqualFold(rec.Protocol, q.Protocol) {
			continue
		}
		if q.AppProtocol != "" && !strings.EqualFold(rec.AppProtocol, q.AppProtocol) {
			continue
		}
		res.Matched++
		if len(res.Records) < q.Limit {
			res.Records = append(res.Records, rec)
		} else {
			res.Truncated = true
		}
	}
	return res
}
