// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package metricexport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/zyvorai/netra/internal/tsdb"
)

func TestSnappyRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	random := make([]byte, 70000)
	rng.Read(random)
	repetitive := bytes.Repeat([]byte("netra_system_cpu{instance=\"n1\",dimension=\"user\"} "), 4000)
	for name, in := range map[string][]byte{"empty": nil, "short": []byte("abc"), "random": random, "repetitive": repetitive, "run": bytes.Repeat([]byte{'a'}, 1000)} {
		enc := snappyEncode(in)
		out, err := snappyDecode(enc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(out, in) {
			t.Fatalf("%s: round trip mismatch", name)
		}
		if name == "repetitive" && len(enc) > len(in)/10 {
			t.Errorf("repetitive input compressed only to %d of %d bytes", len(enc), len(in))
		}
	}
	if _, err := snappyDecode([]byte{5, 0xff}); err == nil {
		t.Error("corrupt input decoded")
	}
}

func testStore(t *testing.T, start int64, n int) *tsdb.DB {
	t.Helper()
	db, err := tsdb.Open(tsdb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cpu := tsdb.Series{Context: "system.cpu", Chart: "system.cpu", Dimension: "user", Family: "cpu", Units: "%"}
	net := tsdb.Series{Context: "net.net", Chart: "net.eth0", Dimension: "received", Labels: map[string]string{"device": "eth0", "instance": "spoof"}}
	for i := 0; i < n; i++ {
		_ = db.Append(tsdb.Sample{Series: cpu, T: start + int64(i), V: float64(i % 10)})
		_ = db.Append(tsdb.Sample{Series: net, T: start + int64(i), V: 100})
	}
	return db
}

type memSink struct {
	mu      sync.Mutex
	batches [][]Series
	fail    bool
}

func (m *memSink) Name() string { return "mem" }
func (m *memSink) Send(_ context.Context, b []Series) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("down")
	}
	m.batches = append(m.batches, b)
	return nil
}

func TestExporterDownsamplesFiltersAndRetries(t *testing.T) {
	start := int64(1_700_000_000)
	db := testStore(t, start, 120)
	sink := &memSink{}
	e, err := New(Options{Sources: func() []tsdb.Source { return []tsdb.Source{{Node: "n1", DB: db}} }, Sink: sink, Resolution: 10 * time.Second, Contexts: []string{"system.*"}})
	if err != nil {
		t.Fatal(err)
	}
	// First contact exports only the latest complete bucket.
	now := time.Unix(start+65, 0)
	if err := e.Once(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(sink.batches) != 1 || len(sink.batches[0]) != 1 {
		t.Fatalf("batches %+v", sink.batches)
	}
	s := sink.batches[0][0]
	if s.Series.Context != "system.cpu" || len(s.Points) != 1 || s.Points[0].T != start+60 || s.Points[0].V != 4.5 {
		t.Fatalf("first batch %+v", s)
	}
	// An outage keeps the cursor, so the next success covers the gap.
	sink.fail = true
	if err := e.Once(context.Background(), time.Unix(start+85, 0)); err == nil {
		t.Fatal("expected failure")
	}
	sink.fail = false
	if err := e.Once(context.Background(), time.Unix(start+105, 0)); err != nil {
		t.Fatal(err)
	}
	got := sink.batches[1][0].Points
	if len(got) != 4 || got[0].T != start+70 || got[3].T != start+100 {
		t.Fatalf("catch-up points %+v", got)
	}
	st := e.Status()
	if st.Failures != 1 || st.Sent != 5 || st.Batches != 2 {
		t.Fatalf("status %+v", st)
	}
}

func TestRemoteWriteEncoding(t *testing.T) {
	var got []byte
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr = r.Header
		b, _ := io.ReadAll(r.Body)
		got, _ = snappyDecode(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	rw := &RemoteWrite{URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer t"}}
	batch := []Series{{Node: "n1", Series: tsdb.Series{Context: "net.net", Chart: "net.eth0", Dimension: "received", Labels: map[string]string{"device": "eth0", "instance": "spoof"}}, Points: []Point{{T: 100, V: 1.5}, {T: 110, V: 2}}}}
	if err := rw.Send(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if hdr.Get("Content-Encoding") != "snappy" || hdr.Get("X-Prometheus-Remote-Write-Version") != "0.1.0" || hdr.Get("Authorization") != "Bearer t" {
		t.Fatalf("headers %v", hdr)
	}
	labels, samples := decodeWriteRequest(t, got)
	want := [][2]string{{"__name__", "netra_net_net"}, {"chart", "net.eth0"}, {"device", "eth0"}, {"dimension", "received"}, {"instance", "n1"}}
	if len(labels) != len(want) {
		t.Fatalf("labels %v", labels)
	}
	for i := range want {
		if labels[i] != want[i] {
			t.Fatalf("label %d = %v, want %v", i, labels[i], want[i])
		}
	}
	if len(samples) != 2 || samples[0] != [2]float64{1.5, 100000} || samples[1] != [2]float64{2, 110000} {
		t.Fatalf("samples %v", samples)
	}
}

// decodeWriteRequest parses one TimeSeries back out with protowire.
func decodeWriteRequest(t *testing.T, b []byte) ([][2]string, [][2]float64) {
	t.Helper()
	var labels [][2]string
	var samples [][2]float64
	num, typ, n := protowire.ConsumeTag(b)
	if num != 1 || typ != protowire.BytesType {
		t.Fatalf("bad WriteRequest tag")
	}
	ts, _ := protowire.ConsumeBytes(b[n:])
	for len(ts) > 0 {
		num, _, n := protowire.ConsumeTag(ts)
		ts = ts[n:]
		msg, m := protowire.ConsumeBytes(ts)
		ts = ts[m:]
		switch num {
		case 1:
			var kv [2]string
			for len(msg) > 0 {
				f, _, k := protowire.ConsumeTag(msg)
				msg = msg[k:]
				s, l := protowire.ConsumeString(msg)
				msg = msg[l:]
				kv[f-1] = s
			}
			labels = append(labels, kv)
		case 2:
			var v, ts float64
			for len(msg) > 0 {
				f, _, k := protowire.ConsumeTag(msg)
				msg = msg[k:]
				if f == 1 {
					x, l := protowire.ConsumeFixed64(msg)
					v = math.Float64frombits(x)
					msg = msg[l:]
				} else {
					x, l := protowire.ConsumeVarint(msg)
					ts = float64(x)
					msg = msg[l:]
				}
			}
			samples = append(samples, [2]float64{v, ts})
		}
	}
	return labels, samples
}

func TestOTLPBody(t *testing.T) {
	var body map[string]any
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
	}))
	defer srv.Close()
	o := &OTLP{Endpoint: srv.URL, Resource: map[string]string{"k8s.cluster.name": "lab"}}
	batch := []Series{{Node: "n1", Series: tsdb.Series{Context: "system.cpu", Chart: "system.cpu", Dimension: "user", Units: "%"}, Points: []Point{{T: 100, V: 3}}}}
	if err := o.Send(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if path != "/v1/metrics" {
		t.Fatalf("path %q", path)
	}
	rm := body["resourceMetrics"].([]any)[0].(map[string]any)
	m := rm["scopeMetrics"].([]any)[0].(map[string]any)["metrics"].([]any)[0].(map[string]any)
	if m["name"] != "netra.system.cpu" || m["unit"] != "%" {
		t.Fatalf("metric %v", m)
	}
	dp := m["gauge"].(map[string]any)["dataPoints"].([]any)[0].(map[string]any)
	if dp["timeUnixNano"] != "100000000000" || dp["asDouble"].(float64) != 3 {
		t.Fatalf("data point %v", dp)
	}
}

func TestGraphiteSink(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lines := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var out []string
		sc := bufio.NewScanner(c)
		for sc.Scan() {
			out = append(out, sc.Text())
		}
		lines <- out
	}()
	g := &Graphite{Addr: ln.Addr().String()}
	batch := []Series{{Node: "node-1.lab", Series: tsdb.Series{Chart: "net.eth0", Dimension: "received"}, Points: []Point{{T: 100, V: 1.25}, {T: 110, V: 2}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.Send(ctx, batch); err != nil {
		t.Fatal(err)
	}
	got := <-lines
	want := "netra.node-1_lab.net_eth0.received 1.25 100"
	if len(got) != 2 || got[0] != want || !strings.HasSuffix(got[1], " 2 110") {
		t.Fatalf("lines %q", got)
	}
}

func TestParseHeaders(t *testing.T) {
	h := ParseHeaders("Authorization=Bearer abc, X-Scope-OrgID=tenant1,bad")
	if h["Authorization"] != "Bearer abc" || h["X-Scope-OrgID"] != "tenant1" || len(h) != 2 {
		t.Fatalf("%v", h)
	}
}
