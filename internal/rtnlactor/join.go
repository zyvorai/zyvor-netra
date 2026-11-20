// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package rtnlactor

import (
	"sort"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

const (
	// windowBefore is how long before a change's notification reached the agent its
	// request may have been made: the request runs, then the multicast notification
	// is queued, then the agent's goroutine wakes and reads it, which under load can
	// take a few hundred milliseconds.
	windowBefore = 750 * time.Millisecond
	// windowAfter is slack for the two clocks and for a notification read before the
	// ring-buffer record was.
	windowAfter = 100 * time.Millisecond

	maxRecords = 8192
	// dropQuiet is how long around a ring-buffer overflow a change is left
	// unattributed rather than declared kernel-originated.
	dropQuiet = 10 * time.Second
	// maxAlternatives bounds the process names listed for an ambiguous match.
	maxAlternatives = 3
)

// Resolver maps a cgroup id to the pod it belongs to; ok is false for a host
// process or a cgroup the agent does not know.
type Resolver func(cgroupID uint64) (namespace, pod, workload string, ok bool)

// Joiner keeps the recent requests and attributes recorded changes to them.
type Joiner struct {
	mu      sync.Mutex
	resolve Resolver
	started time.Time
	// netns is the network namespace changes are recorded in (0: not checked).
	netns uint32

	ring      []Record
	head      int
	size      int
	records   uint64
	dropped   uint64
	droppedAt time.Time
}

// NewJoiner returns a Joiner for changes recorded in network namespace netns
// (SelfNetNS for the agent; 0 disables the check). resolve may be nil (no pod names).
func NewJoiner(resolve Resolver, netns uint32) *Joiner {
	j := newJoiner(resolve, time.Now())
	j.netns = netns
	return j
}

func newJoiner(resolve Resolver, started time.Time) *Joiner {
	return &Joiner{resolve: resolve, started: started, ring: make([]Record, maxRecords)}
}

// Add stores one request. It is the callback the sensor's Run loop is given, so it
// never blocks.
func (j *Joiner) Add(r Record) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.records++
	j.ring[(j.head+j.size)%len(j.ring)] = r
	if j.size == len(j.ring) {
		j.head = (j.head + 1) % len(j.ring)
		return
	}
	j.size++
}

// NoteDropped records the kernel's running count of requests it could not buffer.
// When it grows, changes around that moment are left unattributed.
func (j *Joiner) NoteDropped(total uint64, at time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if total > j.dropped {
		j.droppedAt = at
	}
	j.dropped = total
}

// Status is the sensor's state, for the report.
func (j *Joiner) Status() models.NetlinkActorStatus {
	j.mu.Lock()
	defer j.mu.Unlock()
	return models.NetlinkActorStatus{Available: true, Dropped: j.dropped, Records: j.records}
}

// requestTypes are the RTM_* types whose handling produces this recorded change,
// or nil for a kind that no request produces (the recorder's own overrun events).
func requestTypes(e models.NetlinkEvent) []uint16 {
	del := e.Action == "delete"
	switch e.Kind {
	case models.NetlinkKindLink:
		if del {
			return []uint16{RTMDelLink}
		}
		return []uint16{RTMNewLink, RTMSetLink}
	case models.NetlinkKindAddress:
		if del {
			return []uint16{RTMDelAddr}
		}
		return []uint16{RTMNewAddr}
	case models.NetlinkKindRoute:
		if del {
			return []uint16{RTMDelRoute}
		}
		return []uint16{RTMNewRoute}
	case models.NetlinkKindNeighbor:
		if del {
			return []uint16{RTMDelNeigh}
		}
		return []uint16{RTMNewNeigh}
	}
	return nil
}

// linkBareLen is NLMSG_HDRLEN plus sizeof(struct ifinfomsg): a link request with
// nothing after them.
const linkBareLen = 16 + 16

func isLinkRequest(t uint16) bool { return t == RTMNewLink || t == RTMDelLink || t == RTMSetLink }

func hasType(types []uint16, t uint16) bool {
	for _, x := range types {
		if x == t {
			return true
		}
	}
	return false
}

// Attribute says who asked for a recorded change. It returns the requester (nil
// unless exactly one, or several, matched) and the origin: "process" when a
// request matches, "kernel" when none does and the sensor was in a position to see
// one, and "" when it cannot tell.
//
// "kernel" is a strong claim, so it is made only when nothing weakens it: the
// sensor was already running when the change happened, the kernel did not drop
// requests around then, and the ring of recent requests still reaches back far
// enough to have held a match.
func (j *Joiner) Attribute(e models.NetlinkEvent) (*models.NetlinkActor, string) {
	types := requestTypes(e)
	if types == nil || e.ObservedAt.IsZero() {
		return nil, ""
	}
	lo, hi := e.ObservedAt.Add(-windowBefore), e.ObservedAt.Add(windowAfter)

	j.mu.Lock()
	defer j.mu.Unlock()
	byTGID := map[uint32]Record{}
	uncertain := false
	for i := 0; i < j.size; i++ {
		r := j.ring[(j.head+i)%len(j.ring)]
		if r.Wall.Before(lo) || r.Wall.After(hi) || !hasType(types, r.Type) {
			continue
		}
		// Interface indexes are per network namespace: a request made in another one
		// (a pod's CNI setup, say) cannot explain a change here, whatever its ifindex.
		// The kernel program already drops them; this is the second guard, and a record
		// whose namespace is unknown (0) is kept.
		if j.netns != 0 && r.NetNS != 0 && r.NetNS != j.netns {
			continue
		}
		// A request that names an interface only explains a change on that
		// interface. A create names none, so it matches any.
		if r.IfIndex != 0 && e.InterfaceIndex != 0 && r.IfIndex != uint32(e.InterfaceIndex) {
			continue
		}
		if isLinkRequest(r.Type) && r.Flags&NLMFCreate == 0 && r.IfIndex == 0 {
			switch {
			case r.IfName != "":
				// Names its device only by name: it explains only that device.
				if e.Interface != "" && r.IfName != e.Interface {
					continue
				}
			case r.Len != 0 && r.Len <= linkBareLen:
				// No index, no name and no attributes: iproute2's probe at the start of
				// every `ip link` command. It targets nothing and changes nothing, so it
				// explains nothing; matching it would credit whoever ran `ip link` at that
				// moment with every link change around it.
				continue
			default:
				// It has attributes but none that names its device the way we read (an
				// alternative name, say). It may or may not be about this device: not a
				// match, and not proof of a kernel-originated change either.
				uncertain = true
				continue
			}
		}
		// A route request names its destination: it only explains the change to that
		// prefix, so two processes adding routes on one interface in the same instant
		// are still told apart. A request whose destination is unknown matches any.
		if r.Dest != "" && e.Destination != "" && r.Dest != e.Destination {
			continue
		}
		byTGID[r.TGID] = r // the latest request of each process
	}

	switch len(byTGID) {
	case 0:
		if uncertain || j.cannotSee(e.ObservedAt, lo) {
			return nil, ""
		}
		return nil, models.NetlinkOriginKernel
	case 1:
		for _, r := range byTGID {
			return j.actor(r, models.NetlinkActorProbable, 1, nil), models.NetlinkOriginProcess
		}
	}
	comms := map[string]bool{}
	for _, r := range byTGID {
		comms[r.Comm] = true
	}
	alt := make([]string, 0, len(comms))
	for c := range comms {
		alt = append(alt, c)
	}
	sort.Strings(alt)
	if len(alt) > maxAlternatives {
		alt = alt[:maxAlternatives]
	}
	return &models.NetlinkActor{Confidence: models.NetlinkActorAmbiguous, Candidates: len(byTGID), Alternatives: alt}, models.NetlinkOriginProcess
}

// cannotSee reports whether the absence of a matching request proves nothing.
// Called with j.mu held.
func (j *Joiner) cannotSee(at, windowStart time.Time) bool {
	// The sensor started too recently to have seen a request from before the window.
	if at.Sub(j.started) < windowBefore {
		return true
	}
	// The kernel dropped requests around then.
	if !j.droppedAt.IsZero() {
		d := at.Sub(j.droppedAt)
		if d < 0 {
			d = -d
		}
		if d < dropQuiet {
			return true
		}
	}
	// The ring wrapped and its oldest request is already newer than the window.
	if j.size == len(j.ring) && j.ring[j.head].Wall.After(windowStart) {
		return true
	}
	return false
}

func (j *Joiner) actor(r Record, confidence string, candidates int, alt []string) *models.NetlinkActor {
	a := &models.NetlinkActor{
		Confidence: confidence, Comm: r.Comm, PID: r.TGID, CgroupID: r.CgroupID,
		Candidates: candidates, Alternatives: alt,
	}
	if j.resolve != nil {
		if ns, pod, workload, ok := j.resolve(r.CgroupID); ok {
			a.Namespace, a.Pod, a.Workload = ns, pod, workload
		}
	}
	return a
}
