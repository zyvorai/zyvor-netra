// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package metricstream moves per-second metrics from each agent (child) to
// netrad (parent). The agent's tier-0 store doubles as the replay buffer:
// after a disconnect or a parent restart the parent reports the newest
// second it holds for the node and the agent resends everything after it.
package metricstream

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/zyvorai/netra/internal/tsdb"
)

// Path is the parent's ingest endpoint.
const Path = "/api/v1/agents/metrics"

// Batch is one POST body.
type Batch struct {
	Node   string       `json:"node"`
	From   int64        `json:"from"` // exclusive
	To     int64        `json:"to"`   // inclusive
	Series []WireSeries `json:"series,omitempty"`
}

// WireSeries carries points as [t, v, anomalous] triples.
type WireSeries struct {
	tsdb.Series
	Points [][3]float64 `json:"points"`
}

// Response is the parent's answer.
type Response struct {
	// PrevLastT is the node's newest stored second before this batch.
	PrevLastT int64 `json:"prevLastT"`
	LastT     int64 `json:"lastT"`
	Stored    int   `json:"stored"`
	// Gap means PrevLastT is older than Batch.From, so storing the batch
	// would leave a hole. Nothing was stored; the agent replays from
	// PrevLastT so seconds arrive in order.
	Gap bool `json:"gap,omitempty"`
}

// FromSeriesPoints converts a tsdb batch to the wire form, dropping
// non-finite values that JSON cannot carry.
func FromSeriesPoints(in []tsdb.SeriesPoints) []WireSeries {
	out := make([]WireSeries, 0, len(in))
	for _, sp := range in {
		ws := WireSeries{Series: sp.Series, Points: make([][3]float64, 0, len(sp.Points))}
		for _, p := range sp.Points {
			if math.IsNaN(p.V) || math.IsInf(p.V, 0) {
				continue
			}
			a := 0.0
			if p.Anomalous {
				a = 1
			}
			ws.Points = append(ws.Points, [3]float64{float64(p.T), p.V, a})
		}
		if len(ws.Points) > 0 {
			out = append(out, ws)
		}
	}
	return out
}

// Samples flattens a batch into tsdb samples in time order per series.
func (b *Batch) Samples() []tsdb.Sample {
	var out []tsdb.Sample
	for _, ws := range b.Series {
		for _, p := range ws.Points {
			out = append(out, tsdb.Sample{Series: ws.Series, T: int64(p[0]), V: p[1], Anomalous: p[2] != 0})
		}
	}
	return out
}

// Encode gzips the JSON form of b.
func Encode(b *Batch) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MaxDecoded caps the decompressed size of one batch.
const MaxDecoded = 64 << 20

// Decode reads a gzip or plain JSON batch, refusing more than MaxDecoded
// bytes after decompression.
func Decode(r io.Reader, gzipped bool) (*Batch, error) {
	if gzipped {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer zr.Close()
		r = zr
	}
	lr := &io.LimitedReader{R: r, N: MaxDecoded + 1}
	var b Batch
	if err := json.NewDecoder(lr).Decode(&b); err != nil {
		if lr.N <= 0 {
			return nil, errors.New("batch exceeds size limit")
		}
		return nil, err
	}
	return &b, nil
}
