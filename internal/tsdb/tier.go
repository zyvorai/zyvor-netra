// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package tsdb

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// tierStore keeps the rollups of one tier.
type tierStore interface {
	write(id uint32, r Rollup) error
	read(ids map[uint32]bool, after, before int64, fn func(id uint32, r Rollup)) error
	enforce(now int64, retention int64, quota int64) error
	flush() error
	sizeBytes() int64
	close() error
}

// memTier keeps a capped ring of rollups per series. Used when the DB has no
// directory, which is the agent default.
type memTier struct {
	mu   sync.Mutex
	cap  int
	rows map[uint32][]Rollup
}

func newMemTier(capRows int) *memTier {
	return &memTier{cap: capRows, rows: map[uint32][]Rollup{}}
}

func (m *memTier) write(id uint32, r Rollup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := append(m.rows[id], r)
	if len(rows) > m.cap {
		rows = append(rows[:0:0], rows[len(rows)-m.cap:]...)
	}
	m.rows[id] = rows
	return nil
}

func (m *memTier) read(ids map[uint32]bool, after, before int64, fn func(uint32, Rollup)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range ids {
		for _, r := range m.rows[id] {
			if r.Start >= after && r.Start <= before {
				fn(id, r)
			}
		}
	}
	return nil
}

func (m *memTier) enforce(now, retention, _ int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, rows := range m.rows {
		i := sort.Search(len(rows), func(i int) bool { return rows[i].Start >= now-retention })
		if i == len(rows) {
			delete(m.rows, id)
		} else if i > 0 {
			m.rows[id] = append(rows[:0:0], rows[i:]...)
		}
	}
	return nil
}

func (m *memTier) flush() error { return nil }

func (m *memTier) sizeBytes() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for _, rows := range m.rows {
		n += int64(len(rows)) * 40
	}
	return n
}

func (m *memTier) close() error { return nil }

// diskTier appends fixed-size records to segment files, one file per
// segment window, named by the window's start second.
//
// Record layout (little endian, 24 bytes): series id u32, offset from the
// segment start u32, min f32, max f32, avg f32, count u16, anomalous u16.
type diskTier struct {
	mu      sync.Mutex
	dir     string
	segSpan int64
	curSeg  int64
	f       *os.File
	w       *bufio.Writer
}

const recordSize = 24

func newDiskTier(dir string, segSpan int64) (*diskTier, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &diskTier{dir: dir, segSpan: segSpan, curSeg: -1}, nil
}

func (d *diskTier) segPath(start int64) string {
	return filepath.Join(d.dir, strconv.FormatInt(start, 10)+".seg")
}

func (d *diskTier) write(id uint32, r Rollup) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	seg := r.Start - r.Start%d.segSpan
	if seg != d.curSeg {
		if err := d.closeCurrent(); err != nil {
			return err
		}
		f, err := os.OpenFile(d.segPath(seg), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return err
		}
		d.f, d.w, d.curSeg = f, bufio.NewWriterSize(f, 64<<10), seg
	}
	var buf [recordSize]byte
	binary.LittleEndian.PutUint32(buf[0:], id)
	binary.LittleEndian.PutUint32(buf[4:], uint32(r.Start-seg))
	binary.LittleEndian.PutUint32(buf[8:], math.Float32bits(float32(r.Min)))
	binary.LittleEndian.PutUint32(buf[12:], math.Float32bits(float32(r.Max)))
	binary.LittleEndian.PutUint32(buf[16:], math.Float32bits(float32(r.Avg())))
	binary.LittleEndian.PutUint16(buf[20:], uint16(min(r.Count, math.MaxUint16)))
	binary.LittleEndian.PutUint16(buf[22:], uint16(min(r.Anomalous, math.MaxUint16)))
	_, err := d.w.Write(buf[:])
	return err
}

func (d *diskTier) closeCurrent() error {
	if d.f == nil {
		return nil
	}
	err := d.w.Flush()
	if cerr := d.f.Close(); err == nil {
		err = cerr
	}
	d.f, d.w, d.curSeg = nil, nil, -1
	return err
}

func (d *diskTier) segments() ([]int64, error) {
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return nil, err
	}
	var out []int64
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".seg") {
			continue
		}
		start, err := strconv.ParseInt(strings.TrimSuffix(name, ".seg"), 10, 64)
		if err == nil {
			out = append(out, start)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (d *diskTier) read(ids map[uint32]bool, after, before int64, fn func(uint32, Rollup)) error {
	d.mu.Lock()
	if d.w != nil {
		if err := d.w.Flush(); err != nil {
			d.mu.Unlock()
			return err
		}
	}
	segs, err := d.segments()
	d.mu.Unlock()
	if err != nil {
		return err
	}
	for _, seg := range segs {
		if seg+d.segSpan <= after || seg > before {
			continue
		}
		if err := d.readSegment(seg, ids, after, before, fn); err != nil {
			return err
		}
	}
	return nil
}

func (d *diskTier) readSegment(seg int64, ids map[uint32]bool, after, before int64, fn func(uint32, Rollup)) error {
	f, err := os.Open(d.segPath(seg))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 256<<10)
	var buf [recordSize]byte
	for {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		id := binary.LittleEndian.Uint32(buf[0:])
		if !ids[id] {
			continue
		}
		start := seg + int64(binary.LittleEndian.Uint32(buf[4:]))
		if start < after || start > before {
			continue
		}
		count := uint32(binary.LittleEndian.Uint16(buf[20:]))
		avg := float64(math.Float32frombits(binary.LittleEndian.Uint32(buf[16:])))
		fn(id, Rollup{
			Start:     start,
			Min:       float64(math.Float32frombits(binary.LittleEndian.Uint32(buf[8:]))),
			Max:       float64(math.Float32frombits(binary.LittleEndian.Uint32(buf[12:]))),
			Sum:       avg * float64(count),
			Count:     count,
			Anomalous: uint32(binary.LittleEndian.Uint16(buf[22:])),
		})
	}
}

// enforce deletes segments older than retention, then the oldest segments
// until the tier fits inside quota. The segment being written is kept.
func (d *diskTier) enforce(now, retention, quota int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	segs, err := d.segments()
	if err != nil {
		return err
	}
	type seg struct {
		start int64
		size  int64
	}
	var all []seg
	var total int64
	for _, s := range segs {
		st, err := os.Stat(d.segPath(s))
		if err != nil {
			continue
		}
		if s+d.segSpan < now-retention && s != d.curSeg {
			if err := os.Remove(d.segPath(s)); err != nil {
				return fmt.Errorf("evict segment: %w", err)
			}
			continue
		}
		all = append(all, seg{s, st.Size()})
		total += st.Size()
	}
	for i := 0; quota > 0 && total > quota && i < len(all); i++ {
		if all[i].start == d.curSeg {
			continue
		}
		if err := os.Remove(d.segPath(all[i].start)); err != nil {
			return fmt.Errorf("evict segment: %w", err)
		}
		total -= all[i].size
	}
	return nil
}

func (d *diskTier) flush() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.w == nil {
		return nil
	}
	return d.w.Flush()
}

func (d *diskTier) sizeBytes() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	segs, _ := d.segments()
	var n int64
	for _, s := range segs {
		if st, err := os.Stat(d.segPath(s)); err == nil {
			n += st.Size()
		}
	}
	return n
}

func (d *diskTier) close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closeCurrent()
}
