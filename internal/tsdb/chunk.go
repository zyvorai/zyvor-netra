// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package tsdb

import (
	"math"
	"math/bits"
)

// chunkCap is the number of samples one tier-0 chunk holds before a new
// chunk is started. At 1s resolution one chunk covers four minutes.
const chunkCap = 240

// bitWriter appends single bits and bit groups to a byte slice.
type bitWriter struct {
	b    []byte
	free uint8 // unused low bits in the last byte
}

func (w *bitWriter) writeBit(on bool) {
	if w.free == 0 {
		w.b = append(w.b, 0)
		w.free = 8
	}
	if on {
		w.b[len(w.b)-1] |= 1 << (w.free - 1)
	}
	w.free--
}

func (w *bitWriter) writeBits(v uint64, n int) {
	for n > 0 {
		if w.free == 0 {
			w.b = append(w.b, 0)
			w.free = 8
		}
		take := min(n, int(w.free))
		shift := n - take
		part := byte((v >> uint(shift)) & ((1 << uint(take)) - 1))
		w.b[len(w.b)-1] |= part << (w.free - uint8(take))
		w.free -= uint8(take)
		n -= take
	}
}

type bitReader struct {
	b   []byte
	pos int // bit position
}

func (r *bitReader) readBit() (bool, bool) {
	if r.pos >= len(r.b)*8 {
		return false, false
	}
	v := r.b[r.pos/8]&(1<<(7-uint(r.pos%8))) != 0
	r.pos++
	return v, true
}

func (r *bitReader) readBits(n int) (uint64, bool) {
	var v uint64
	for i := 0; i < n; i++ {
		bit, ok := r.readBit()
		if !ok {
			return 0, false
		}
		v <<= 1
		if bit {
			v |= 1
		}
	}
	return v, true
}

// chunk stores up to chunkCap samples using delta-of-delta timestamps and
// XOR-encoded float values, plus one anomaly bit per sample.
type chunk struct {
	first, last int64
	n           int
	w           bitWriter
	prevDelta   int64
	prevV       uint64
	leading     uint8
	trailing    uint8
	anom        [(chunkCap + 63) / 64]uint64
}

func (c *chunk) full() bool { return c.n >= chunkCap }

func (c *chunk) append(t int64, v float64, anomalous bool) {
	vb := math.Float64bits(v)
	switch c.n {
	case 0:
		c.first = t
		c.w.writeBits(uint64(t), 64)
		c.w.writeBits(vb, 64)
		c.leading = 0xff
	case 1:
		delta := t - c.last
		c.w.writeBits(uint64(delta), 32)
		c.prevDelta = delta
		c.writeValue(vb)
	default:
		delta := t - c.last
		dod := delta - c.prevDelta
		switch {
		case dod == 0:
			c.w.writeBit(false)
		case dod >= -63 && dod <= 64:
			c.w.writeBits(0b10, 2)
			c.w.writeBits(uint64(dod)&0x7f, 7)
		case dod >= -255 && dod <= 256:
			c.w.writeBits(0b110, 3)
			c.w.writeBits(uint64(dod)&0x1ff, 9)
		case dod >= -2047 && dod <= 2048:
			c.w.writeBits(0b1110, 4)
			c.w.writeBits(uint64(dod)&0xfff, 12)
		default:
			c.w.writeBits(0b1111, 4)
			c.w.writeBits(uint64(dod), 64)
		}
		c.prevDelta = delta
		c.writeValue(vb)
	}
	if anomalous {
		c.anom[c.n/64] |= 1 << uint(c.n%64)
	}
	c.prevV = vb
	c.last = t
	c.n++
}

func (c *chunk) writeValue(vb uint64) {
	x := vb ^ c.prevV
	if x == 0 {
		c.w.writeBit(false)
		return
	}
	c.w.writeBit(true)
	lead := uint8(bits.LeadingZeros64(x))
	trail := uint8(bits.TrailingZeros64(x))
	if lead > 31 {
		lead = 31
	}
	if c.leading != 0xff && lead >= c.leading && trail >= c.trailing {
		c.w.writeBit(false)
		sig := 64 - int(c.leading) - int(c.trailing)
		c.w.writeBits(x>>c.trailing, sig)
		return
	}
	c.leading, c.trailing = lead, trail
	c.w.writeBit(true)
	c.w.writeBits(uint64(lead), 5)
	sig := 64 - int(lead) - int(trail)
	c.w.writeBits(uint64(sig&63), 6) // 64 encodes as 0
	c.w.writeBits(x>>trail, sig)
}

// forEach decodes the chunk in order. fn returning false stops iteration.
func (c *chunk) forEach(fn func(t int64, v float64, anomalous bool) bool) {
	r := bitReader{b: c.w.b}
	var t, delta int64
	var vb uint64
	var leading, trailing uint8
	for i := 0; i < c.n; i++ {
		switch i {
		case 0:
			tt, _ := r.readBits(64)
			v, _ := r.readBits(64)
			t, vb = int64(tt), v
		case 1:
			d, _ := r.readBits(32)
			delta = int64(int32(uint32(d)))
			t += delta
			vb, leading, trailing = readValue(&r, vb, leading, trailing)
		default:
			var dod int64
			b, _ := r.readBit()
			if b {
				b2, _ := r.readBit()
				if !b2 {
					v, _ := r.readBits(7)
					dod = signExtend(v, 7)
				} else {
					b3, _ := r.readBit()
					if !b3 {
						v, _ := r.readBits(9)
						dod = signExtend(v, 9)
					} else {
						b4, _ := r.readBit()
						if !b4 {
							v, _ := r.readBits(12)
							dod = signExtend(v, 12)
						} else {
							v, _ := r.readBits(64)
							dod = int64(v)
						}
					}
				}
			}
			delta += dod
			t += delta
			vb, leading, trailing = readValue(&r, vb, leading, trailing)
		}
		anom := c.anom[i/64]&(1<<uint(i%64)) != 0
		if !fn(t, math.Float64frombits(vb), anom) {
			return
		}
	}
}

func readValue(r *bitReader, prev uint64, leading, trailing uint8) (uint64, uint8, uint8) {
	b, _ := r.readBit()
	if !b {
		return prev, leading, trailing
	}
	ctrl, _ := r.readBit()
	if ctrl {
		l, _ := r.readBits(5)
		s, _ := r.readBits(6)
		sig := int(s)
		if sig == 0 {
			sig = 64
		}
		leading = uint8(l)
		trailing = uint8(64 - int(leading) - sig)
	}
	sig := 64 - int(leading) - int(trailing)
	x, _ := r.readBits(sig)
	return prev ^ (x << trailing), leading, trailing
}

// signExtend interprets the low n bits of v as a value in [-(2^(n-1)-1), 2^(n-1)].
// The encoder masks values in that range; 2^(n-1) itself round-trips as the
// positive maximum because the negative minimum is never written.
func signExtend(v uint64, n int) int64 {
	half := uint64(1) << uint(n-1)
	if v > half {
		return int64(v) - int64(uint64(1)<<uint(n))
	}
	return int64(v)
}

// sizeBytes is the approximate in-memory footprint of the chunk.
func (c *chunk) sizeBytes() int { return cap(c.w.b) + 96 }
