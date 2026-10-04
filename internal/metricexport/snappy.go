// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package metricexport

import (
	"encoding/binary"
	"errors"
)

// snappyEncode produces the Snappy block format (not the framed stream
// format) that Prometheus remote write requires. It is a small greedy
// encoder: a hash table of 4-byte prefixes finds back-references, which are
// emitted as copy elements; everything else is literals. The ratio is a bit
// below the reference encoder but the output is fully compatible.
func snappyEncode(src []byte) []byte {
	dst := binary.AppendUvarint(make([]byte, 0, len(src)/2+16), uint64(len(src)))
	if len(src) < 16 {
		return emitLiteral(dst, src)
	}
	const tableBits = 14
	var table [1 << tableBits]int32
	hash := func(u uint32) uint32 { return (u * 0x1e35a7bd) >> (32 - tableBits) }
	load := func(i int) uint32 { return binary.LittleEndian.Uint32(src[i:]) }

	lit := 0
	i := 0
	for i+4 <= len(src) {
		h := hash(load(i))
		cand := int(table[h]) - 1
		table[h] = int32(i + 1)
		if cand < 0 || i-cand > 65535 || load(cand) != load(i) {
			i++
			continue
		}
		dst = emitLiteral(dst, src[lit:i])
		n := 4
		for i+n < len(src) && src[cand+n] == src[i+n] {
			n++
		}
		dst = emitCopy(dst, i-cand, n)
		i += n
		lit = i
	}
	return emitLiteral(dst, src[lit:])
}

func emitLiteral(dst, lit []byte) []byte {
	for len(lit) > 0 {
		chunk := lit
		if len(chunk) > 65536 {
			chunk = chunk[:65536]
		}
		n := len(chunk) - 1
		switch {
		case n < 60:
			dst = append(dst, byte(n)<<2)
		case n < 1<<8:
			dst = append(dst, 60<<2, byte(n))
		default:
			dst = append(dst, 61<<2, byte(n), byte(n>>8))
		}
		dst = append(dst, chunk...)
		lit = lit[len(chunk):]
	}
	return dst
}

// emitCopy writes copy-2 elements (offset < 65536, length 1..64).
func emitCopy(dst []byte, offset, length int) []byte {
	for length > 0 {
		n := min(length, 64)
		// A trailing copy shorter than 4 bytes is fine for copy-2 elements.
		dst = append(dst, byte(n-1)<<2|2, byte(offset), byte(offset>>8))
		length -= n
	}
	return dst
}

var errSnappyCorrupt = errors.New("snappy: corrupt input")

// snappyDecode decodes the block format; used by tests and the receiver
// fixtures.
func snappyDecode(src []byte) ([]byte, error) {
	n, k := binary.Uvarint(src)
	if k <= 0 || n > 64<<20 {
		return nil, errSnappyCorrupt
	}
	src = src[k:]
	dst := make([]byte, 0, n)
	for len(src) > 0 {
		tag := src[0]
		switch tag & 3 {
		case 0:
			l := int(tag >> 2)
			src = src[1:]
			switch {
			case l < 60:
			case l == 60:
				if len(src) < 1 {
					return nil, errSnappyCorrupt
				}
				l, src = int(src[0]), src[1:]
			case l == 61:
				if len(src) < 2 {
					return nil, errSnappyCorrupt
				}
				l, src = int(binary.LittleEndian.Uint16(src)), src[2:]
			default:
				return nil, errSnappyCorrupt
			}
			l++
			if len(src) < l {
				return nil, errSnappyCorrupt
			}
			dst = append(dst, src[:l]...)
			src = src[l:]
		case 1:
			if len(src) < 2 {
				return nil, errSnappyCorrupt
			}
			l := int(tag>>2&7) + 4
			off := int(tag>>5)<<8 | int(src[1])
			src = src[2:]
			if err := copyBack(&dst, off, l); err != nil {
				return nil, err
			}
		case 2:
			if len(src) < 3 {
				return nil, errSnappyCorrupt
			}
			l := int(tag>>2) + 1
			off := int(binary.LittleEndian.Uint16(src[1:]))
			src = src[3:]
			if err := copyBack(&dst, off, l); err != nil {
				return nil, err
			}
		default:
			if len(src) < 5 {
				return nil, errSnappyCorrupt
			}
			l := int(tag>>2) + 1
			off := int(binary.LittleEndian.Uint32(src[1:]))
			src = src[5:]
			if err := copyBack(&dst, off, l); err != nil {
				return nil, err
			}
		}
	}
	if uint64(len(dst)) != n {
		return nil, errSnappyCorrupt
	}
	return dst, nil
}

func copyBack(dst *[]byte, off, l int) error {
	d := *dst
	if off <= 0 || off > len(d) {
		return errSnappyCorrupt
	}
	start := len(d) - off
	for i := 0; i < l; i++ {
		d = append(d, d[start+i])
	}
	*dst = d
	return nil
}
