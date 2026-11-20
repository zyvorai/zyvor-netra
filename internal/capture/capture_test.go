// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package capture

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildRawEvent constructs a raw capture_events ringbuf record the same
// shape bpf/netra_capture.c would submit: a fixed eventHeaderLen+MaxCapLen
// buffer with only the first capLen data bytes meaningful.
func buildRawEvent(t *testing.T, tsNS uint64, ifindex, origLen, capLen uint32, direction, family, protocol byte, data []byte) []byte {
	t.Helper()
	buf := make([]byte, eventHeaderLen+MaxCapLen)
	binary.LittleEndian.PutUint64(buf[0:8], tsNS)
	binary.LittleEndian.PutUint32(buf[8:12], ifindex)
	binary.LittleEndian.PutUint32(buf[12:16], origLen)
	binary.LittleEndian.PutUint32(buf[16:20], capLen)
	buf[20], buf[21], buf[22] = direction, family, protocol
	copy(buf[eventHeaderLen:], data)
	return buf
}

func TestDecodeRingbufRecord(t *testing.T) {
	data := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	raw := buildRawEvent(t, 123456789, 2, 1500, uint32(len(data)), 1, 4, 6, data)
	ev, err := DecodeRingbufRecord(raw)
	if err != nil {
		t.Fatalf("DecodeRingbufRecord: %v", err)
	}
	if ev.TimestampNS != 123456789 || ev.Ifindex != 2 || ev.OrigLen != 1500 || ev.CapLen != uint32(len(data)) {
		t.Fatalf("header mismatch: %+v", ev)
	}
	if ev.Direction != 1 || ev.Family != 4 || ev.Protocol != 6 {
		t.Fatalf("flags mismatch: %+v", ev)
	}
	if !bytes.Equal(ev.Data, data) {
		t.Fatalf("data mismatch: got %x want %x", ev.Data, data)
	}
}

func TestDecodeRingbufRecordTooShort(t *testing.T) {
	if _, err := DecodeRingbufRecord(make([]byte, 4)); err == nil {
		t.Fatal("expected error for a too-short record")
	}
}

func TestDecodeRingbufRecordClampsOversizedCapLen(t *testing.T) {
	data := []byte{1, 2, 3}
	// A corrupt/adversarial cap_len larger than the buffer must never
	// panic or read out of bounds — it should clamp to what's available.
	raw := buildRawEvent(t, 1, 1, 1500, 999999, 1, 4, 17, data)
	ev, err := DecodeRingbufRecord(raw)
	if err != nil {
		t.Fatalf("DecodeRingbufRecord: %v", err)
	}
	if len(ev.Data) != MaxCapLen {
		t.Fatalf("expected clamp to MaxCapLen, got %d", len(ev.Data))
	}
}

func TestFrameRoundTrip(t *testing.T) {
	f := Frame{ObservedAtUnixNano: 1_700_000_000_123456789, OrigLen: 1500, Direction: 2, Family: 6, Protocol: 17, Data: []byte("hello capture")}
	got, err := DecodeFrame(EncodeFrame(f))
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if got.ObservedAtUnixNano != f.ObservedAtUnixNano || got.OrigLen != f.OrigLen || got.Direction != f.Direction || got.Family != f.Family || got.Protocol != f.Protocol {
		t.Fatalf("frame header mismatch: got %+v want %+v", got, f)
	}
	if !bytes.Equal(got.Data, f.Data) {
		t.Fatalf("frame data mismatch: got %q want %q", got.Data, f.Data)
	}
}

func TestDecodeFrameTooShort(t *testing.T) {
	if _, err := DecodeFrame(make([]byte, 4)); err == nil {
		t.Fatal("expected error for a too-short frame")
	}
}

func TestDecodeFrameLengthMismatch(t *testing.T) {
	raw := EncodeFrame(Frame{Data: []byte("abc")})
	raw = append(raw, 0, 0, 0) // corrupt: trailing bytes not reflected in the length header
	if _, err := DecodeFrame(raw); err == nil {
		t.Fatal("expected error for a length-mismatched frame")
	}
}

func TestPCAPWriteHeaderAndRecord(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePCAPHeader(&buf); err != nil {
		t.Fatalf("WritePCAPHeader: %v", err)
	}
	if buf.Len() != pcapGlobalHdrLen {
		t.Fatalf("global header length = %d, want %d", buf.Len(), pcapGlobalHdrLen)
	}
	if magic := binary.LittleEndian.Uint32(buf.Bytes()[0:4]); magic != pcapMagic {
		t.Fatalf("magic = %#x, want %#x", magic, pcapMagic)
	}
	f := Frame{ObservedAtUnixNano: 2_000_000_000, OrigLen: 64, Data: []byte("packet")}
	if err := WritePCAPRecord(&buf, f); err != nil {
		t.Fatalf("WritePCAPRecord: %v", err)
	}
	rec := buf.Bytes()[pcapGlobalHdrLen:]
	if got := binary.LittleEndian.Uint32(rec[8:12]); got != uint32(len(f.Data)) {
		t.Fatalf("incl_len = %d, want %d", got, len(f.Data))
	}
	if got := binary.LittleEndian.Uint32(rec[12:16]); got != f.OrigLen {
		t.Fatalf("orig_len = %d, want %d", got, f.OrigLen)
	}
	if !bytes.Equal(rec[pcapRecordHdrLen:], f.Data) {
		t.Fatalf("record data mismatch: got %q want %q", rec[pcapRecordHdrLen:], f.Data)
	}
}
