// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package listenq

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	tcpSynRecv = 3
	tcpListen  = 10

	sizeofDiagReq = 56 // struct inet_diag_req_v2
	sizeofDiagMsg = 72 // struct inet_diag_msg

	// struct inet_diag_msg offsets.
	offState  = 1
	offSport  = 4  // idiag_sport, big endian
	offSrc    = 8  // idiag_src[4], 16 bytes
	offRQueue = 56 // idiag_rqueue: for LISTEN, the accept queue length
	offWQueue = 60 // idiag_wqueue: for LISTEN, the configured backlog
)

// diagReq is a dump request for TCP sockets of one family in the given states.
// The socket id is left zero, which a dump treats as "any".
type diagReq struct {
	family uint8
	states uint32
}

func (r *diagReq) Len() int { return sizeofDiagReq }

func (r *diagReq) Serialize() []byte {
	b := make([]byte, sizeofDiagReq)
	b[0] = r.family
	b[1] = unix.IPPROTO_TCP
	binary.NativeEndian.PutUint32(b[4:], r.states)
	return b
}

type diagSock struct {
	family    string
	addr      net.IP
	port      uint16
	rq, wq    uint32
	stateBits uint8
}

func dump(family uint8, states uint32) ([]diagSock, error) {
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	req.AddData(&diagReq{family: family, states: states})
	var out []diagSock
	err := req.ExecuteIter(unix.NETLINK_INET_DIAG, nl.SOCK_DIAG_BY_FAMILY, func(msg []byte) bool {
		if len(msg) < sizeofDiagMsg {
			return true
		}
		s := diagSock{
			stateBits: msg[offState],
			port:      binary.BigEndian.Uint16(msg[offSport:]),
			rq:        binary.NativeEndian.Uint32(msg[offRQueue:]),
			wq:        binary.NativeEndian.Uint32(msg[offWQueue:]),
		}
		if family == unix.AF_INET6 {
			s.family = "ipv6"
			s.addr = net.IP(append([]byte(nil), msg[offSrc:offSrc+16]...))
		} else {
			s.family = "ipv4"
			s.addr = net.IP(append([]byte(nil), msg[offSrc:offSrc+4]...))
		}
		out = append(out, s)
		return true
	})
	// An interrupted dump (the socket table changed under it) is still a usable
	// best-effort answer for a sampler that runs again in a few seconds.
	if err != nil && !errors.Is(err, nl.ErrDumpInterrupted) {
		return nil, err
	}
	return out, nil
}

// Dump returns every listening TCP socket in this network namespace, with the
// half-open connection count of each. The agent runs in the host network
// namespace, so these are the host's listeners.
func Dump() ([]Listener, error) {
	var out []Listener
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		listeners, err := dump(fam, 1<<tcpListen)
		if err != nil {
			return nil, fmt.Errorf("inet_diag listeners (family %d): %w", fam, err)
		}
		// Request sockets are best effort: their absence must not hide the
		// accept queues, which are the primary signal.
		half, herr := dump(fam, 1<<tcpSynRecv)
		if herr != nil {
			half = nil
		}
		start := len(out)
		for _, s := range listeners {
			out = append(out, Listener{Family: s.family, Addr: s.addr.String(), Port: s.port, Queue: s.rq, Max: s.wq})
		}
		attributeSynRecv(out[start:], half)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Addr < out[j].Addr
	})
	return out, nil
}

// attributeSynRecv adds each half-open connection to the listener it is
// waiting on: the listener bound to exactly its local address and port, else
// the wildcard one on that port.
func attributeSynRecv(listeners []Listener, half []diagSock) {
	for _, h := range half {
		exact, wild := -1, -1
		for i, l := range listeners {
			if l.Port != h.port {
				continue
			}
			ip := net.ParseIP(l.Addr)
			switch {
			case ip.Equal(h.addr):
				exact = i
			case ip.IsUnspecified():
				wild = i
			}
		}
		switch {
		case exact >= 0:
			listeners[exact].SynRecv++
		case wild >= 0:
			listeners[wild].SynRecv++
		}
	}
}
