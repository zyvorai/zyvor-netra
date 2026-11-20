// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package afcapture

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/zyvorai/netra/internal/capture"
)

// readBufSize is sized generously above capture.MaxCapLen: the cBPF
// filter's own return value already truncates what the kernel delivers to
// (at most) spec.SnapLen (or 0xffff/full-frame when unset), so this only
// needs to be large enough to never itself be the truncating factor.
const readBufSize = capture.MaxCapLen + 256

// Open starts an AF_PACKET capture session across every named interface,
// merging frames from all of them into one channel — see afcapture.go's
// package doc for why this produces capture.Frame directly rather than a
// parallel type. Per-interface listen/filter/promiscuous-mode setup
// happens synchronously (so a bad interface name or a CAP_NET_RAW denial
// is returned as an error from Open itself, not discovered later in a
// goroutine); the actual packet reads run in one goroutine per interface
// for the session's lifetime.
//
// Unlike the eBPF path, there is no separate in-kernel expiry backstop
// here (no BPF program at all is involved) — session duration is enforced
// entirely by internal/agent's existing 3s reconcile tick canceling this
// session's context when the desired capture expires or is cleared, the
// same primary mechanism the eBPF path already relies on for its own
// duration enforcement (its kernel-side expires_ns is documented there as
// a backstop for a slow reconcile, not the primary enforcement).
func Open(ctx context.Context, ifaces []string, spec capture.SpecValue) (*Session, error) {
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("afcapture: no interfaces configured")
	}
	filter, err := compileFilter(spec)
	if err != nil {
		return nil, fmt.Errorf("afcapture: compile filter: %w", err)
	}

	conns := make([]*packet.Conn, 0, len(ifaces))
	closeAll := func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}
	for _, name := range ifaces {
		conn, err := listenInterface(name, filter)
		if err != nil {
			closeAll()
			return nil, err
		}
		conns = append(conns, conn)
	}

	cctx, cancel := context.WithCancel(ctx)
	out := make(chan capture.Frame, 256)
	limiter := newRateLimiter(spec.MaxPPS)

	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Add(1)
		go func(conn *packet.Conn) {
			defer wg.Done()
			readLoop(cctx, conn, out, limiter, spec.SnapLen)
		}(conn)
	}
	// Unblocks every reader's blocking rc.Read on cancellation — closing
	// the conn is what actually wakes a goroutine parked in Recvfrom.
	go func() {
		<-cctx.Done()
		closeAll()
	}()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	return &Session{frames: out, cancel: cancel, done: done}, nil
}

func listenInterface(name string, filter []bpf.RawInstruction) (*packet.Conn, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("afcapture: interface %s: %w", name, err)
	}
	// mdlayher/packet's Listen takes the protocol in host order and performs
	// the htons itself before bind — passing htons(ETH_P_ALL) double-swaps on
	// little-endian and binds ETH_P_ALL<<8, which silently receives nothing.
	conn, err := packet.Listen(ifi, packet.Raw, unix.ETH_P_ALL, &packet.Config{Filter: filter})
	if err != nil {
		return nil, fmt.Errorf("afcapture: listen on %s: %w", name, err)
	}
	// Promiscuous mode is needed because this agent runs hostNetwork: true
	// — the bound interface is the host's, and traffic for other pods on
	// this node is not link-layer-destined to this interface's own MAC
	// without it. The eBPF TC hooks see this traffic for free since they
	// sit on the qdisc path regardless of destination MAC; a raw socket
	// does not.
	if err := conn.SetPromiscuous(true); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("afcapture: set promiscuous on %s: %w", name, err)
	}
	return conn, nil
}

// readLoop reads frames off conn until it's closed (by the caller's
// cancellation watcher) or a fatal error occurs. mdlayher/packet's own
// Conn.ReadFrom cannot be used here: its returned Addr only carries
// HardwareAddr, discarding the PACKET_OUTGOING vs PACKET_HOST signal
// (unix.SockaddrLinklayer.Pkttype) that capture.Frame.Direction needs to
// distinguish egress from ingress — so this reads the raw fd directly via
// SyscallConn to recover it.
func readLoop(ctx context.Context, conn *packet.Conn, out chan<- capture.Frame, limiter *rateLimiter, snapLen uint16) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	buf := make([]byte, readBufSize)
	for {
		var (
			n    int
			from unix.Sockaddr
			rerr error
		)
		cerr := rc.Read(func(fd uintptr) bool {
			n, from, rerr = unix.Recvfrom(int(fd), buf, 0)
			return rerr != unix.EAGAIN
		})
		if cerr != nil {
			return // socket closed (session ending) or a fatal RawConn error
		}
		if rerr != nil || n <= 0 {
			continue
		}
		if !limiter.allow() {
			continue // matched the filter but over the session's MaxPPS cap
		}
		dir := dirIngress
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			dir = dirEgress
		}
		capLen := n
		// Defensive second bound: the cBPF filter's own RetConstant already
		// truncates what the kernel delivers to at most snapLen (or a full
		// frame when unset), so this should rarely actually fire.
		if snapLen > 0 && capLen > int(snapLen) {
			capLen = int(snapLen)
		}
		if capLen > capture.MaxCapLen {
			capLen = capture.MaxCapLen
		}
		data := make([]byte, capLen)
		copy(data, buf[:capLen])
		family, proto := classify(data)
		frame := capture.Frame{
			ObservedAtUnixNano: time.Now().UnixNano(),
			OrigLen:            uint32(n),
			Direction:          dir,
			Family:             family,
			Protocol:           proto,
			Data:               data,
		}
		select {
		case out <- frame:
		case <-ctx.Done():
			return
		}
	}
}
