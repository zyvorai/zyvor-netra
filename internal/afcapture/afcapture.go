// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package afcapture is the AF_PACKET-based packet-capture backend: a
// userspace raw-socket alternative to bpf/netra_capture.c's in-kernel TCX
// observer (internal/agent's eBPF-ringbuf path). It produces the exact
// same internal/capture.Frame values the eBPF path already produces, so
// the agent's WS-streaming loop, the controller relay, and the browser
// live-view/pcap-download code need no changes to support this backend —
// see docs/capture.md for the two backends' tradeoffs.
//
// This package needs zero bpf/*.c changes and no BPF toolchain: AF_PACKET
// is a Linux socket family, not an eBPF hook. The only "BPF" involved is
// classic BPF (cBPF, see filter.go) — a much older, unrelated mechanism
// used only for in-kernel packet filtering on the raw socket, assembled at
// runtime in Go via golang.org/x/net/bpf.
package afcapture

import (
	"context"

	"github.com/zyvorai/netra/internal/capture"
)

// Direction values match bpf/netra_capture.c's DIR_INGRESS/DIR_EGRESS
// #defines exactly, since both backends feed the same capture.Frame.
const (
	dirIngress uint8 = 1
	dirEgress  uint8 = 2
)

// Session is one AF_PACKET capture session, possibly spanning several
// interfaces (frames from all of them are merged into one channel) — the
// AF_PACKET-side counterpart to the eBPF path's ringbuf.Reader, adapted to
// the same captureBackend shape internal/agent's runCaptureStream expects.
type Session struct {
	frames chan capture.Frame
	cancel context.CancelFunc
	done   chan struct{}
}

// Frames returns the channel of decoded frames. Closed when the session
// stops (Close, context cancellation, or every interface reader exiting).
func (s *Session) Frames() <-chan capture.Frame { return s.frames }

// Close stops every interface reader and waits for them to exit.
func (s *Session) Close() error {
	s.cancel()
	<-s.done
	return nil
}
