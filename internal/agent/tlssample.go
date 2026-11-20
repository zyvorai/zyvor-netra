// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/l7sample"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/sslprobe"
)

// attachTLSUprobes starts the TLS plaintext sampler. It observes the bytes an
// application hands to OpenSSL before they are encrypted and the bytes it gets
// back after decryption, so it is the most sensitive thing Netra can do and is OFF
// by default: NETRA_TLS_UPROBES=auto|required|off, default off. auto degrades with
// the reason reported; required fails startup. Only bounded metadata is exported
// (operation name and coarse outcome; never paths, headers, cookies or bodies),
// and NETRA_TLS_UPROBES_COMMS restricts it to named processes in the kernel.
func (a *Agent) attachTLSUprobes() error {
	mode := strings.ToLower(env("NETRA_TLS_UPROBES", "off"))
	if mode == "off" || mode == "" {
		return nil
	}
	fail := func(why error) error {
		if mode == "required" {
			return fmt.Errorf("TLS plaintext sampling (NETRA_TLS_UPROBES=required): %w", why)
		}
		a.sslWhy = why.Error()
		a.log.Warn("TLS plaintext sampling unavailable; continuing without it", "error", why)
		return nil
	}
	var comms []string
	for _, c := range strings.Split(env("NETRA_TLS_UPROBES_COMMS", ""), ",") {
		if c = strings.TrimSpace(c); c != "" {
			comms = append(comms, c)
		}
	}
	gap := envDuration("NETRA_TLS_UPROBES_GAP", 100*time.Millisecond)
	p, err := sslprobe.Load(sslprobe.Options{ObjectPath: a.sslObject, MinGap: gap, Comms: comms, Log: a.log})
	if err != nil {
		return fail(err)
	}
	a.sslProber = p
	a.tlsCounters = l7sample.NewCounters()
	a.sslComms = comms
	added, err := p.Scan()
	if err != nil {
		_ = p.Close()
		a.sslProber = nil
		return fail(err)
	}
	a.hooks = append(a.hooks, "tls-uprobes")
	for _, name := range []string{"netra_ssl_write", "netra_ssl_write_ex", "netra_ssl_read", "netra_ssl_read_ret", "netra_ssl_read_ex", "netra_ssl_read_ex_ret"} {
		a.markAttached(name)
	}
	a.log.Info("TLS plaintext sampling attached (plaintext is parsed in the agent and never exported)",
		"libraries", added, "processAllowlist", comms, "minGap", gap.String())
	return nil
}

// observeTLS classifies one plaintext fragment and counts it. The bytes are not
// retained.
func (a *Agent) observeTLS(e sslprobe.Event) {
	o, role, ok := sslprobe.Classify(e.Write, e.Data)
	a.tlsCounters.ObserveObs(o, ok, role)
}

// rescanTLS looks for libssl files that appeared since the last scan: a container
// started later brings its own copy of the library.
func (a *Agent) rescanTLS(ctx context.Context) {
	t := time.NewTicker(envDuration("NETRA_TLS_UPROBES_RESCAN", 30*time.Second))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if added, err := a.sslProber.Scan(); err != nil {
				a.log.Warn("TLS sampler rescan", "error", err)
			} else if len(added) > 0 {
				a.log.Info("TLS sampler attached to new libraries", "libraries", added)
			}
		}
	}
}

// readTLSSample returns nil when TLS sampling is off, and an Unavailable summary
// when it tried and could not start.
func (a *Agent) readTLSSample() *models.TLSSampleSummary {
	if a.sslProber == nil {
		if a.sslWhy == "" {
			return nil
		}
		why := a.sslWhy
		if len(why) > maxWhy {
			why = why[:maxWhy]
		}
		return &models.TLSSampleSummary{Unavailable: why}
	}
	ks, err := a.sslProber.KernelStats()
	if err != nil {
		a.log.Warn("read TLS sampler counters", "error", err)
	}
	return summarizeTLS(a.sslProber.Libraries(), a.sslComms, ks, err == nil, a.tlsCounters.Snapshot())
}

// summarizeTLS builds the report from the kernel counters and the parsed counts.
func summarizeTLS(libs, comms []string, ks sslprobe.KernelStats, ksOK bool, snap l7sample.Snapshot) *models.TLSSampleSummary {
	out := &models.TLSSampleSummary{Attached: true, Libraries: libs, Comms: comms}
	if ksOK {
		out.Eligible, out.Emitted, out.RateLimited, out.RingbufFull = ks.Eligible, ks.Emitted, ks.RateLimited, ks.RingbufFull
		out.ReadFail, out.CommFiltered = ks.ReadFail, ks.CommFiltered
		if ks.Emitted > 0 {
			out.ScaleFactor = float64(ks.Eligible) / float64(ks.Emitted)
		}
	}
	out.Seen, out.Classified, out.Overflow = snap.Seen, snap.Classified, snap.Overflow
	// Same shape and bounds as the packet-level sampler's summary.
	l7 := summarizeL7(nil, l7sample.KernelStats{}, false, snap)
	out.Protocols, out.Hosts = l7.Protocols, l7.Hosts
	return out
}
