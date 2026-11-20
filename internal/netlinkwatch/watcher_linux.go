// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package netlinkwatch

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/zyvorai/netra/internal/models"
)

const snapshotInterval = 30 * time.Second

var (
	// recvBuffer is the kernel receive buffer of each subscription. The default
	// (~208 KiB) overflows in a route or neighbor storm; an overflow is ENOBUFS
	// and, in this library, ends the subscription. A variable only so the
	// real-kernel test can shrink it to force an overflow.
	recvBuffer = 1 << 20
	// drainHook, when set, runs once per received route update. Production never
	// sets it; the real-kernel test uses it to slow the reader so a route storm
	// overflows the (shrunk) buffer deterministically.
	drainHook func()
)

// Start attaches read-only RTNL multicast subscriptions in the current network
// namespace (the agent runs hostNetwork) and takes an initial full snapshot.
// It never returns an error on Linux: a failed snapshot or subscription is
// reported through Report().Error and retried, so a transient fault does not
// leave the node without a recorder until the next restart.
func Start(parent context.Context, capacity int) (*Watcher, error) {
	ctx, cancel := context.WithCancel(parent)
	w := newWatcher(capacity)
	w.stop = cancel

	_ = w.refresh(collectSnapshot)
	go w.runSnapshots(ctx, collectSnapshot, snapshotInterval)
	go w.supervise(ctx, "link", w.startLinks)
	go w.supervise(ctx, "address", w.startAddrs)
	go w.supervise(ctx, "route", w.startRoutes)
	go w.supervise(ctx, "neighbor", w.startNeighbors)
	return w, nil
}

// lastError keeps the newest error the library reported through its callback.
type lastError struct {
	mu  sync.Mutex
	msg string
}

func (l *lastError) set(err error) {
	l.mu.Lock()
	l.msg = err.Error()
	l.mu.Unlock()
}

func (l *lastError) get() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.msg
}

func (w *Watcher) startLinks(ctx context.Context) (<-chan struct{}, func() string, error) {
	ch := make(chan netlink.LinkUpdate, 64)
	var last lastError
	if err := netlink.LinkSubscribeWithOptions(ch, ctx.Done(), netlink.LinkSubscribeOptions{
		ErrorCallback: last.set, ReceiveBufferSize: recvBuffer,
	}); err != nil {
		return nil, nil, err
	}
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for u := range ch {
			if e, ok := linkEvent(u); ok {
				w.append(e)
			}
		}
	}()
	return closed, last.get, nil
}

func (w *Watcher) startAddrs(ctx context.Context) (<-chan struct{}, func() string, error) {
	ch := make(chan netlink.AddrUpdate, 128)
	var last lastError
	if err := netlink.AddrSubscribeWithOptions(ch, ctx.Done(), netlink.AddrSubscribeOptions{
		ErrorCallback: last.set, ReceiveBufferSize: recvBuffer,
	}); err != nil {
		return nil, nil, err
	}
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for u := range ch {
			w.append(addrEvent(u))
		}
	}()
	return closed, last.get, nil
}

func (w *Watcher) startRoutes(ctx context.Context) (<-chan struct{}, func() string, error) {
	ch := make(chan netlink.RouteUpdate, 128)
	var last lastError
	if err := netlink.RouteSubscribeWithOptions(ch, ctx.Done(), netlink.RouteSubscribeOptions{
		ErrorCallback: last.set, ReceiveBufferSize: recvBuffer,
	}); err != nil {
		return nil, nil, err
	}
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for u := range ch {
			if drainHook != nil {
				drainHook()
			}
			w.append(routeEvent(u))
		}
	}()
	return closed, last.get, nil
}

func (w *Watcher) startNeighbors(ctx context.Context) (<-chan struct{}, func() string, error) {
	ch := make(chan netlink.NeighUpdate, 128)
	var last lastError
	if err := netlink.NeighSubscribeWithOptions(ch, ctx.Done(), netlink.NeighSubscribeOptions{
		ErrorCallback: last.set, ReceiveBufferSize: recvBuffer,
	}); err != nil {
		return nil, nil, err
	}
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for u := range ch {
			w.recordNeighbor(neighEvent(u))
		}
	}()
	return closed, last.get, nil
}

func linkEvent(u netlink.LinkUpdate) (models.NetlinkEvent, bool) {
	link := u.Link
	if link == nil {
		return models.NetlinkEvent{}, false
	}
	a := link.Attrs()
	return models.NetlinkEvent{
		Kind: models.NetlinkKindLink, Action: rtnlAction(u.Header.Type),
		InterfaceIndex: a.Index, Interface: a.Name, LinkType: link.Type(),
		MTU: a.MTU, State: a.OperState.String(), Flags: a.Flags.String(), MasterIndex: a.MasterIndex,
	}, true
}

func addrEvent(u netlink.AddrUpdate) models.NetlinkEvent {
	action := "delete"
	if u.NewAddr {
		action = "new"
	}
	return models.NetlinkEvent{
		Kind: models.NetlinkKindAddress, Action: action, InterfaceIndex: u.LinkIndex,
		Family: familyOfIPs(u.LinkAddress.IP), Address: ipNetString(&u.LinkAddress),
	}
}

func routeEvent(u netlink.RouteUpdate) models.NetlinkEvent {
	r := u.Route
	gw, oif := r.Gw, r.LinkIndex
	if len(gw) == 0 && len(r.MultiPath) > 0 {
		gw = r.MultiPath[0].Gw
		if oif == 0 {
			oif = r.MultiPath[0].LinkIndex
		}
	}
	return models.NetlinkEvent{
		Kind: models.NetlinkKindRoute, Action: rtnlAction(u.Type), InterfaceIndex: oif,
		Family: routeFamily(r, gw), Destination: routeDestination(r.Dst),
		Gateway: ipString(gw), Source: ipString(r.Src), Table: r.Table, Priority: r.Priority,
	}
}

func neighEvent(u netlink.NeighUpdate) models.NetlinkEvent {
	n := u.Neigh
	return models.NetlinkEvent{
		Kind: models.NetlinkKindNeighbor, Action: rtnlAction(u.Type), InterfaceIndex: n.LinkIndex,
		Family: familyName(n.Family), Address: ipString(n.IP), MAC: hardwareString(n.HardwareAddr),
		State: neighborState(n.State),
	}
}

func routeFamily(r netlink.Route, gw net.IP) string {
	if r.Family == familyV4 || r.Family == familyV6 {
		return familyName(r.Family)
	}
	var dst net.IP
	if r.Dst != nil {
		dst = r.Dst.IP
	}
	return familyOfIPs(dst, gw, r.Src)
}

func rtnlAction(typ uint16) string {
	switch typ {
	case unix.RTM_DELLINK, unix.RTM_DELADDR, unix.RTM_DELROUTE, unix.RTM_DELNEIGH:
		return "delete"
	default:
		return "new"
	}
}

// collectSnapshot dumps the full link, address, route and neighbor state.
// Routes are listed across every table: RouteList alone skips all but main,
// and policy-routed CNIs keep their routes elsewhere.
func collectSnapshot() (models.NetlinkSnapshot, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return models.NetlinkSnapshot{}, fmt.Errorf("list links: %w", err)
	}
	var out models.NetlinkSnapshot
	names := make(map[int]string, len(links))
	for _, link := range links {
		a := link.Attrs()
		names[a.Index] = a.Name
		out.Links = append(out.Links, models.NetlinkLink{
			Index: a.Index, Name: a.Name, Type: link.Type(), MTU: a.MTU,
			State: a.OperState.String(), Flags: a.Flags.String(), MasterIndex: a.MasterIndex,
		})
		addrs, addrErr := netlink.AddrList(link, netlink.FAMILY_ALL)
		if addrErr != nil {
			continue
		}
		for _, ad := range addrs {
			out.Addresses = append(out.Addresses, models.NetlinkAddress{
				InterfaceIndex: a.Index, Interface: a.Name, Family: familyOfIPs(ad.IP),
				Address: ipNetString(ad.IPNet), Scope: ad.Scope, Flags: ad.Flags,
			})
		}
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return models.NetlinkSnapshot{}, fmt.Errorf("list routes: %w", err)
	}
	for _, r := range routes {
		gw, oif := r.Gw, r.LinkIndex
		if len(gw) == 0 && len(r.MultiPath) > 0 {
			gw = r.MultiPath[0].Gw
			if oif == 0 {
				oif = r.MultiPath[0].LinkIndex
			}
		}
		out.Routes = append(out.Routes, models.NetlinkRoute{
			Family: routeFamily(r, gw), Destination: routeDestination(r.Dst), Gateway: ipString(gw),
			Source: ipString(r.Src), InterfaceIndex: oif, Interface: names[oif], Table: r.Table,
			Priority: r.Priority, Protocol: int(r.Protocol), Scope: int(r.Scope), Type: r.Type,
		})
	}
	neighbors, err := netlink.NeighList(0, netlink.FAMILY_ALL)
	if err != nil {
		return models.NetlinkSnapshot{}, fmt.Errorf("list neighbors: %w", err)
	}
	for _, n := range neighbors {
		out.Neighbors = append(out.Neighbors, models.NetlinkNeighbor{
			Family: familyName(n.Family), Address: ipString(n.IP), MAC: hardwareString(n.HardwareAddr),
			InterfaceIndex: n.LinkIndex, Interface: names[n.LinkIndex], State: neighborState(n.State), Flags: n.Flags,
		})
	}
	return out, nil
}
