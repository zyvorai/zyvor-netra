// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build metricsveth

package metricsmoke

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/anomaly"
	"github.com/zyvorai/netra/internal/collectors"
	"github.com/zyvorai/netra/internal/metricstream"
	"github.com/zyvorai/netra/internal/tsdb"
)

// TestFeedController streams this host's per-second metrics to
// NETRA_SMOKE_SERVER for NETRA_SMOKE_SECONDS, scoring anomalies with
// models short enough to train inside the smoke's quiet phase.
func TestFeedController(t *testing.T) {
	server := os.Getenv("NETRA_SMOKE_SERVER")
	if server == "" {
		t.Skip("NETRA_SMOKE_SERVER not set")
	}
	secs, _ := strconv.Atoi(os.Getenv("NETRA_SMOKE_SECONDS"))
	if secs <= 0 {
		secs = 180
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	db, err := tsdb.Open(tsdb.Options{Tier0Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	det := anomaly.New(anomaly.Options{TrainWindow: 10 * time.Minute, TrainEvery: 15 * time.Second, YoungEvery: 15 * time.Second, MinTrainPoints: 40})
	sched := collectors.NewScheduler(log, func(s []tsdb.Sample) {
		det.Annotate(s)
		_, _ = db.AppendBatch(s)
	}, append(collectors.Host(collectors.Config{}), collectors.NewProcessGroups(collectors.Config{}, 40))...)
	sender := &metricstream.Sender{DB: db, Server: server, Node: os.Getenv("NETRA_SMOKE_NODE"), Key: os.Getenv("NETRA_AGENT_KEY"), Client: &http.Client{Timeout: 10 * time.Second}, Log: log}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	go sched.Run(ctx)
	go sender.Run(ctx)
	// Training must stop before the load starts, or the burst becomes
	// part of what the models call normal.
	trainFor := time.Duration(envInt("NETRA_SMOKE_TRAIN_SECONDS", 70)) * time.Second
	stopTrain := time.After(trainFor)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	training := true
	for {
		select {
		case <-ctx.Done():
			st := det.Stats()
			t.Logf("models=%d sender=%+v", st.Models, sender.Status())
			return
		case <-stopTrain:
			training = false
			t.Logf("training stopped with %d models", det.Stats().Models)
		case now := <-tick.C:
			if training {
				det.TrainDue(db, now, 5000)
			}
		}
	}
}

func envInt(k string, d int) int {
	if n, err := strconv.Atoi(os.Getenv(k)); err == nil && n > 0 {
		return n
	}
	return d
}
