// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package alert

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/notify"
)

func routeGone(node string, at time.Time, more ...models.NetlinkEvent) models.AgentStatus {
	ev := []models.NetlinkEvent{{
		Epoch: 1, Sequence: 1, Kind: "route", Action: "delete", Family: "ipv4", Destination: "default",
		Gateway: "10.0.0.1", Interface: "eth0", Table: 254, ObservedAt: at,
	}}
	ev = append(ev, more...)
	return models.AgentStatus{AgentReport: models.AgentReport{Node: node, Netlink: &models.NetlinkReport{Available: true, Epoch: 1, Events: ev}}}
}

func netlinkEvents(evs []notify.Event) []notify.Event {
	var out []notify.Event
	for _, e := range evs {
		if strings.HasPrefix(e.Kind, "netlink-") {
			out = append(out, e)
		}
	}
	return out
}

// The whole point of the detection: a recorded change becomes a notification,
// once, without anyone querying the API.
func TestRemovedDefaultRouteBecomesACriticalNotificationOnce(t *testing.T) {
	var published []notify.Event
	p := newTestPoller(Config{Cooldown: time.Minute}, &published)
	now := time.Now()
	agents := []models.AgentStatus{routeGone("worker-1", now.Add(-2*time.Minute))}

	got, _ := p.evaluate(now, agents)
	nl := netlinkEvents(got)
	if len(nl) != 1 {
		t.Fatalf("netlink events=%d in %+v", len(nl), got)
	}
	e := nl[0]
	if e.Kind != "netlink-default-route-removed" || e.Severity != "critical" || e.Subject != "worker-1" || e.Source != "health" {
		t.Fatalf("event=%+v", e)
	}
	if !strings.Contains(e.Message, "10.0.0.1") {
		t.Fatalf("message=%q", e.Message)
	}
	// The same condition on the next poll is de-duplicated, not re-sent.
	again, _ := p.evaluate(now.Add(10*time.Second), agents)
	if n := len(netlinkEvents(again)); n != 0 {
		t.Fatalf("%d duplicate notification(s) inside the cooldown", n)
	}
}

func TestRecoveredDefaultRouteStopsAlerting(t *testing.T) {
	var published []notify.Event
	p := newTestPoller(Config{Cooldown: time.Minute}, &published)
	now := time.Now()
	back := models.NetlinkEvent{
		Epoch: 1, Sequence: 2, Kind: "route", Action: "new", Family: "ipv4", Destination: "default",
		Gateway: "10.0.0.2", Interface: "eth0", Table: 254, ObservedAt: now.Add(-time.Minute),
	}
	got, _ := p.evaluate(now, []models.AgentStatus{routeGone("worker-1", now.Add(-2*time.Minute), back)})
	if n := len(netlinkEvents(got)); n != 0 {
		t.Fatalf("alerted on a route that was re-added: %+v", got)
	}
}
