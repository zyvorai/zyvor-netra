// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package capture implements the userspace half of packet-capture
// streaming: decoding bpf/netra_capture.c's ringbuf records, framing them
// for the agent→controller→browser relay, and writing the classic pcap
// file format so a captured session opens directly in Wireshark. The
// kernel-side capture engine itself is a standalone, fail-open TCX
// observer (see that file's header comment) — nothing here can affect a
// packet's verdict, only observe already-forwarded traffic.
package capture

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MaxCapLen must match bpf/netra_capture.c's NETRA_CAP_MAX_LEN — the fixed
// size of every capture_events ringbuf reservation, regardless of a given
// packet's real captured length (the verifier requires reserve() sizes to
// be compile-time constants; see that file's comment on struct
// capture_event for the full reasoning).
const MaxCapLen = 9000

// SpecValue mirrors bpf/netra_capture.c's struct capture_spec byte-for-byte
// (40 bytes total; Go's natural field alignment already matches the C
// struct's __attribute__((packed)) layout with no extra padding needed —
// verified field-by-field against that file's own _Static_assert). Port is
// a plain host-order port number (e.g. 443, not byte-swapped) — the kernel
// side swaps once before comparing to the wire-order value it parses out of
// each packet.
type SpecValue struct {
	Enabled   uint8
	Family    uint8
	Protocol  uint8
	Pad0      uint8
	Host      [16]byte
	Port      uint16
	SnapLen   uint16
	ExpiresNS uint64
	MaxPPS    uint32
	Pad1      uint32
}

// RateValue mirrors struct capture_rate (32 bytes) — the in-kernel
// capture/drop counters internal/agent reads back for status reporting.
type RateValue struct {
	WindowStartSec   uint32
	WindowCount      uint32
	CapturedPackets  uint64
	CapturedBytes    uint64
	DroppedByRateCap uint64
}

// eventHeaderLen is sizeof(struct capture_event) minus its trailing
// data[MaxCapLen] array: ts_ns(8) + ifindex(4) + orig_len(4) + cap_len(4) +
// direction(1) + family(1) + protocol(1) + pad0(1).
const eventHeaderLen = 24

// RingbufEvent is one decoded capture_events record, read straight off the
// kernel ringbuf via cilium/ebpf's ringbuf.Reader (native/little-endian
// byte order, matching the bpfel target and the host it runs on).
type RingbufEvent struct {
	TimestampNS uint64 // bpf_ktime_get_ns() at capture time — boot-relative, not wall-clock; see DecodeRingbufRecord
	Ifindex     uint32
	OrigLen     uint32
	CapLen      uint32
	Direction   uint8
	Family      uint8
	Protocol    uint8
	Data        []byte // raw frame bytes starting at the Ethernet header, length CapLen
}

// DecodeRingbufRecord parses one raw capture_events ringbuf record. The
// record's on-wire size is always sizeof(struct capture_event) — the fixed
// maximum — regardless of how many of its data[] bytes are real capture
// versus unused reservation space, so CapLen (not len(raw)) is what bounds
// the real payload.
//
// TimestampNS is kernel boot time, not Unix time — like every other
// ts_ns field in this codebase (see models.FastPathEvent's TimestampNS),
// callers should stamp their own wall-clock time when they need one (see
// Frame.ObservedAtUnixNano), not attempt to convert this value.
func DecodeRingbufRecord(raw []byte) (RingbufEvent, error) {
	if len(raw) < eventHeaderLen {
		return RingbufEvent{}, fmt.Errorf("capture event too short: %d bytes", len(raw))
	}
	e := RingbufEvent{
		TimestampNS: binary.LittleEndian.Uint64(raw[0:8]),
		Ifindex:     binary.LittleEndian.Uint32(raw[8:12]),
		OrigLen:     binary.LittleEndian.Uint32(raw[12:16]),
		CapLen:      binary.LittleEndian.Uint32(raw[16:20]),
		Direction:   raw[20],
		Family:      raw[21],
		Protocol:    raw[22],
	}
	capLen := max(min(int(e.CapLen), MaxCapLen, len(raw)-eventHeaderLen), 0)
	e.Data = append([]byte(nil), raw[eventHeaderLen:eventHeaderLen+capLen]...)
	return e, nil
}

// Frame is the wire format streamed agent→controller→browser over the
// capture WebSocket (see internal/api/capture.go) — the controller relays
// these byte-for-byte without decoding them, so this is the one format all
// three ends (agent Go, controller Go, browser JS) must agree on.
//
// Layout (all integers little-endian, matching every other binary decode
// in this codebase — see readEvents' use of encoding/binary's native
// order): observedAtUnixNano(8) origLen(4) capLen(4) direction(1)
// family(1) protocol(1) pad(1) data(capLen).
type Frame struct {
	ObservedAtUnixNano int64
	OrigLen            uint32
	Direction          uint8
	Family             uint8
	Protocol           uint8
	Data               []byte
}

const frameHeaderLen = 20

// EncodeFrame serializes f for the WS relay.
func EncodeFrame(f Frame) []byte {
	buf := make([]byte, frameHeaderLen+len(f.Data))
	binary.LittleEndian.PutUint64(buf[0:8], uint64(f.ObservedAtUnixNano))
	binary.LittleEndian.PutUint32(buf[8:12], f.OrigLen)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(f.Data)))
	buf[16] = f.Direction
	buf[17] = f.Family
	buf[18] = f.Protocol
	copy(buf[frameHeaderLen:], f.Data)
	return buf
}

// DecodeFrame is EncodeFrame's inverse — used by cmd/netractl's capture
// tail/pcap-download path, which speaks the same WS protocol as the
// browser.
func DecodeFrame(raw []byte) (Frame, error) {
	if len(raw) < frameHeaderLen {
		return Frame{}, fmt.Errorf("capture frame too short: %d bytes", len(raw))
	}
	capLen := binary.LittleEndian.Uint32(raw[12:16])
	if int(capLen) != len(raw)-frameHeaderLen {
		return Frame{}, fmt.Errorf("capture frame length mismatch: header says %d, have %d", capLen, len(raw)-frameHeaderLen)
	}
	f := Frame{
		ObservedAtUnixNano: int64(binary.LittleEndian.Uint64(raw[0:8])),
		OrigLen:            binary.LittleEndian.Uint32(raw[8:12]),
		Direction:          raw[16],
		Family:             raw[17],
		Protocol:           raw[18],
	}
	f.Data = append([]byte(nil), raw[frameHeaderLen:]...)
	return f, nil
}

// pcapMagic / pcapVersionMajor / pcapVersionMinor / linktypeEthernet are the
// classic (non-pcapng) libpcap file-format constants — chosen so a captured
// session opens directly in Wireshark/tcpdump with no conversion step.
const (
	pcapMagic          = 0xa1b2c3d4
	pcapVersionMajor   = 2
	pcapVersionMinor   = 4
	linktypeEthernet   = 1
	pcapGlobalHdrLen   = 24
	pcapRecordHdrLen   = 16
	pcapDefaultSnapLen = MaxCapLen
)

// WritePCAPHeader writes the classic pcap global file header.
func WritePCAPHeader(w io.Writer) error {
	hdr := make([]byte, pcapGlobalHdrLen)
	binary.LittleEndian.PutUint32(hdr[0:4], pcapMagic)
	binary.LittleEndian.PutUint16(hdr[4:6], pcapVersionMajor)
	binary.LittleEndian.PutUint16(hdr[6:8], pcapVersionMinor)
	binary.LittleEndian.PutUint32(hdr[16:20], pcapDefaultSnapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], linktypeEthernet)
	_, err := w.Write(hdr)
	return err
}

// WritePCAPRecord appends one captured frame using f's own wall-clock
// ObservedAtUnixNano as the record timestamp.
func WritePCAPRecord(w io.Writer, f Frame) error {
	rec := make([]byte, pcapRecordHdrLen+len(f.Data))
	sec := f.ObservedAtUnixNano / 1e9
	usec := (f.ObservedAtUnixNano % 1e9) / 1000
	binary.LittleEndian.PutUint32(rec[0:4], uint32(sec))
	binary.LittleEndian.PutUint32(rec[4:8], uint32(usec))
	binary.LittleEndian.PutUint32(rec[8:12], uint32(len(f.Data)))
	binary.LittleEndian.PutUint32(rec[12:16], f.OrigLen)
	copy(rec[pcapRecordHdrLen:], f.Data)
	_, err := w.Write(rec)
	return err
}
