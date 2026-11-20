package watchlist

import (
	"net/netip"
	"strings"

	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/models"
)

const MaxHits = 500

type Hit struct {
	Type, Value, Kind, Node, Namespace, Pod, Subject string
	Packets, Blocked                                 uint64
}

type Result struct {
	Hits    []Hit `json:"hits"`
	Count   int   `json:"count"`
	Capped  bool  `json:"capped"`
	Checked int   `json:"checked"`
}

func Match(agents []models.AgentStatus, entries []intel.Entry, limit int) Result {
	if limit <= 0 || limit > MaxHits {
		limit = MaxHits
	}
	out := Result{Hits: []Hit{}, Checked: len(entries)}
	for _, e := range entries {
		if len(out.Hits) >= limit {
			break
		}
		switch e.Type {
		case "ip":
			addr, err := netip.ParseAddr(e.Value)
			if err != nil {
				continue
			}
			scanIP(agents, e, addr, nil, &out, limit)
		case "cidr":
			pfx, err := netip.ParsePrefix(e.Value)
			if err != nil {
				continue
			}
			scanIP(agents, e, netip.Addr{}, &pfx, &out, limit)
		case "dns":
			want := strings.ToLower(strings.TrimSuffix(e.Value, "."))
			for _, a := range agents {
				for _, d := range a.DNSHealth {
					if len(out.Hits) >= limit {
						break
					}
					got := strings.ToLower(strings.TrimSuffix(d.Name, "."))
					if got == want || strings.HasSuffix(got, "."+want) {
						hit(&out, e, "dns", a.Node, d.Namespace, d.Pod, d.Name, d.Queries, d.Failures)
					}
				}
			}
		case "sni":
			want := strings.ToLower(strings.TrimSuffix(e.Value, "."))
			for _, a := range agents {
				for _, t := range a.TLSMetadata {
					if len(out.Hits) >= limit {
						break
					}
					got := strings.ToLower(strings.TrimSuffix(t.SNI, "."))
					if got == want || strings.HasSuffix(got, "."+want) {
						hit(&out, e, "sni", a.Node, t.Namespace, t.Pod, t.SNI, t.Handshakes, t.Blocked)
					}
				}
			}
		}
	}
	out.Count = len(out.Hits)
	out.Capped = out.Count >= limit
	return out
}

func scanIP(agents []models.AgentStatus, e intel.Entry, addr netip.Addr, pfx *netip.Prefix, out *Result, limit int) {
	for _, a := range agents {
		for _, st := range a.Stats {
			if len(out.Hits) >= limit {
				return
			}
			if ipHit(st.DestinationIP, addr, pfx) || ipHit(st.SourceIP, addr, pfx) {
				subj := st.DestinationIP
				if st.Namespace != "" && st.Pod != "" {
					subj = st.Namespace + "/" + st.Pod + " → " + st.DestinationIP
				}
				hit(out, e, "flow", a.Node, st.Namespace, st.Pod, subj, st.Packets, st.Blocked)
			}
		}
		for _, ev := range a.Events {
			if len(out.Hits) >= limit {
				return
			}
			if ipHit(ev.DestinationIP, addr, pfx) || ipHit(ev.SourceIP, addr, pfx) {
				blk := uint64(0)
				if ev.Action == "blocked" {
					blk = 1
				}
				hit(out, e, "event", a.Node, ev.Namespace, ev.Pod, ev.Action+" "+ev.DestinationIP, 1, blk)
			}
		}
	}
}

func ipHit(raw string, addr netip.Addr, pfx *netip.Prefix) bool {
	got, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if pfx != nil {
		return pfx.Contains(got)
	}
	return got == addr
}

func hit(out *Result, e intel.Entry, kind, node, ns, pod, subject string, packets, blocked uint64) {
	out.Hits = append(out.Hits, Hit{Type: e.Type, Value: e.Value, Kind: kind, Node: node, Namespace: ns, Pod: pod, Subject: subject, Packets: packets, Blocked: blocked})
}
