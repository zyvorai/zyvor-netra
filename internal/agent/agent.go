// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"

	"github.com/zyvorai/netra/internal/afcapture"
	"github.com/zyvorai/netra/internal/bpfattach"
	"github.com/zyvorai/netra/internal/capture"
	"github.com/zyvorai/netra/internal/cgroupmeta"
	"github.com/zyvorai/netra/internal/dropinfo"
	"github.com/zyvorai/netra/internal/dropreason"
	"github.com/zyvorai/netra/internal/histograms"
	"github.com/zyvorai/netra/internal/kerneldiag"
	"github.com/zyvorai/netra/internal/l7sample"
	"github.com/zyvorai/netra/internal/listenq"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/mtls"
	"github.com/zyvorai/netra/internal/netlinkwatch"
	"github.com/zyvorai/netra/internal/nodeiso"
	"github.com/zyvorai/netra/internal/rtnlactor"
	"github.com/zyvorai/netra/internal/sslprobe"
	"github.com/zyvorai/netra/internal/sysctlaudit"
	"github.com/zyvorai/netra/internal/sysres"
	"github.com/zyvorai/netra/internal/tcpevents"
	"github.com/zyvorai/netra/internal/tlsfp"
	"github.com/zyvorai/netra/internal/workload"
)

var native = binary.LittleEndian // Netra ships a bpfel object.

// mapIterErr treats concurrent BPF map mutation during userspace
// iteration as non-fatal. Partial snapshots are still useful for observe
// reports; failing the whole sync left the controller with zero agents.
func mapIterErr(err error) error {
	if err == nil || errors.Is(err, ebpf.ErrIterationAborted) {
		return nil
	}
	return err
}

type Agent struct {
	log                                *slog.Logger
	server, key, node, object, pinPath string
	cgroupPath                         string
	interfaces, xdpInterfaces          []string
	http                               *http.Client
	// wsDialer mirrors http's TLS trust settings (NETRA_TLS_INSECURE) for
	// the capture-stream WebSocket in runCaptureStream — a bug found via
	// live Chrome verification: websocket.DefaultDialer does not skip
	// certificate verification, so against this chart's self-signed
	// controller cert the dial failed silently (logged, never surfaced to
	// the dashboard) and no capture frame ever left this node.
	wsDialer   *websocket.Dialer
	collection *ebpf.Collection
	links      []link.Link
	// edgeObject/edgeCollection are the standalone edge-TCP-intel BPF
	// object (bpf/netra_edge_intel.c) and its loaded collection — a
	// separate object/collection from the main one, per
	// docs/fluxvm-borrow-backlog.md's "new sensors stay optional separate
	// programs" rule. Its TCX links are appended to the shared a.links
	// slice (Close() already closes those); only the collection itself
	// needs its own Close() call.
	edgeObject     string
	edgeCollection *ebpf.Collection
	// captureObject/captureCollection mirror edgeObject/edgeCollection for
	// bpf/netra_capture.c — a third, independent standalone object with its
	// own collection, per the same "new sensors stay separate programs"
	// rule. activeCapture/captureCancel track the one reconciled capture
	// session (nil/nil when none): activeCapture lets applyCapture no-op on
	// an unchanged desired spec instead of restarting the stream every
	// tick, and captureCancel stops the streaming goroutine on change/stop.
	captureObject     string
	captureCollection *ebpf.Collection
	// tlsfpObject/tlsfpCollection are the standalone ClientHello sampler
	// (bpf/netra_tlsfp.c) — own verifier budget so JA3 works even when
	// netra_l7_* fails to load (docs/l7-metadata.md).
	tlsfpObject     string
	tlsfpCollection *ebpf.Collection
	// tcpEventsObject/tcpEvents are the standalone TCP event tracepoints
	// (bpf/netra_tcpevents.c): retransmit/RST/state-transition counters. The
	// loader owns its own links; Close() calls tcpEvents.Close().
	tcpEventsObject string
	tcpEvents       *tcpevents.Sensor
	// nodeIsoObject/nodeIso are the node-scoped allow-only egress filter
	// (bpf/netra_nodeiso.c, docs/node-isolation.md). nodeIsoWhy is why it is
	// not running; nodeIsoSpec is the last policy received from the
	// controller and nodeIsoImplicit the controller-reachability rules the
	// agent always adds so enforce can never cut it off from its controller.
	nodeIsoObject   string
	nodeIso         *nodeiso.Isolator
	nodeIsoWhy      string
	nodeIsoSpec     *models.NodeIsolationSpec
	nodeIsoImplicit []models.NodeIsolationRule
	// dropInfoObject/dropInfo are the standalone drop-attribution sensor
	// (bpf/netra_dropinfo.c). dropInfoWhy is why it is not running when it
	// tried to and could not (surfaced in the report; empty when off).
	dropInfoObject string
	dropInfo       *dropinfo.Sensor
	dropInfoWhy    string
	// listenQ samples TCP accept-queue depth through inet_diag (no BPF); nil
	// when NETRA_LISTEN_QUEUES=off. listenQWarned limits a persistent failure
	// to one log line rather than one per report.
	listenQ       *listenq.Sampler
	listenQWarned bool
	// netlinkWatch records host link/address/route/neighbor changes over RTNL
	// (docs/netlink-recorder.md); nil when NETRA_NETLINK=off or it could not
	// start (netlinkWhy says why).
	netlinkWatch *netlinkwatch.Watcher
	netlinkWhy   string
	// rtnlSensor names the process behind each recorded change (fentry on
	// rtnetlink_rcv_msg); nil when off or unavailable.
	rtnlSensor *rtnlactor.Sensor
	// bpfSource reads which BPF programs are attached to the interfaces
	// (docs/bpf-attachments.md); nil when NETRA_BPF_ATTACH=off. The rest is the
	// last inventory and what the controller already has, so an unchanged one is
	// not re-sent every report.
	bpfSource   bpfattach.Source
	bpfLast     models.BPFAttachReport
	bpfLastAt   time.Time
	bpfSentHash string
	bpfSentAt   time.Time
	// l7sample* are the sampled application-protocol observer (bpf/netra_l7sample.c,
	// docs/l7-sampling.md). Off unless NETRA_L7_SAMPLE is set; the sampler is nil
	// when it is off or could not start (l7SampleWhy says why).
	l7SampleObject string
	l7Sampler      *l7sample.Sampler
	l7Counters     *l7sample.Counters
	l7SampleWhy    string
	l7SamplePorts  []string
	// ssl* are the TLS plaintext sampler (bpf/netra_ssl.c, docs/tls-plaintext.md):
	// OpenSSL uprobes. Off unless NETRA_TLS_UPROBES is set; the prober is nil when
	// it is off or could not start (sslWhy says why).
	sslObject   string
	sslProber   *sslprobe.Prober
	tlsCounters *l7sample.Counters
	sslWhy      string
	sslComms    []string
	// scans is the latest cost of each map read (mapread.go), for the report.
	scanMu        sync.Mutex
	scans         map[string]models.MapScanStat
	activeCapture *models.CaptureSpec
	captureCancel context.CancelFunc
	// captureBackendErr records why the most recent applyCapture failed to
	// start the requested backend (e.g. "afpacket:CAP_NET_RAW", "ebpf:
	// capture_spec map unavailable"), or "" when the active/most recent
	// request succeeded (or none was ever made). Surfaced to the operator
	// by folding it into AgentReport.MissingMaps — see that field's use in
	// syncOnce — rather than inventing a second node-health channel, since
	// this is the same "requested capability unavailable on this node"
	// category that field already covers.
	captureBackendErr string
	events            chan models.FastPathEvent
	tlsFP             *tlsfp.Detector
	tlsFPCgroups      map[string]uint64 // ja3 → last cgroup_id from datapath samples
	hooks             []string
	lastRevision      uint64
	lastSync          time.Time
	failsafeAfter     time.Duration
	enforceUntil      time.Time
	cgroupEnabled     bool
	workloadMu        sync.RWMutex
	workloadByCgroup  map[uint64]models.WorkloadIdentity
	cgroupCache       map[uint64]cgroupmeta.Identity
	lastCgroupScan    time.Time
	cgroupScanEvery   time.Duration
	scopeMode         string
	selectedCgroups   int

	// procMetaEnabled gates /proc-derived process metadata enrichment
	// (internal/procmeta). Off by default: resolving a host PID's /proc
	// entry from inside the agent container requires hostPID or a host
	// /proc mount, a real expansion of what this already-privileged agent
	// can see beyond what eBPF hooks already surface. See
	// docs/process-metadata.md. The actual enrichment lives in
	// procmeta_linux.go / procmeta_other.go so this file — otherwise
	// portable — does not have to import a Linux-only package directly.
	procMetaEnabled bool

	// attachedProgs tracks which loaded BPF programs successfully attached.
	attachedProgs map[string]bool
	// progStats holds the EnableStats closer so kernel run-count collection stays on.
	progStats io.Closer
	// prevCaps remembers CapEff by pid^startTime for observe-only cap-change watch.
	prevCaps map[uint64]uint64
	// prevNetNS mirrors prevCaps for observe-only network-namespace-change watch.
	prevNetNS map[uint64]uint64
	// prevExeHash mirrors prevCaps for observe-only exe-hash-change watch.
	prevExeHash map[uint64]string
	// prevHostCPU/prevResourceSampleAt hold the host's previous /proc/stat
	// CPU-jiffies sample and when it was taken — CPU usage is a rate, and
	// internal/sysres.Build (stateless, per-request) has no store/window
	// access to diff two samples itself, so the agent keeps its own.
	prevHostCPU          sysres.HostSample
	prevResourceSampleAt time.Time
	// prevWorkloadCPU mirrors prevHostCPU per-workload: cgroup ID -> last
	// cpu.stat usage_usec sample.
	prevWorkloadCPU map[uint64]uint64
	// prevProcJiffies mirrors prevWorkloadCPU for the bounded host-process
	// top: pid -> last utime+stime jiffies. Dropped pids are pruned each tick.
	prevProcJiffies map[uint32]uint64
	// startedAt is set once here at process boot, reported on every cycle as
	// AgentReport.AgentStartedAt — lets consumers (internal/capdrift) detect
	// a recent restart, which resets prevCaps and opens a real blind-spot
	// window for capability-drift detection.
	startedAt time.Time
	// tlsErr is a NETRA_CA_FILE / NETRA_CLIENT_CERT problem found in New; Run
	// returns it rather than starting an agent the controller would reject.
	tlsErr error
	// metrics is the per-second metrics pipeline; nil when disabled.
	metrics *agentMetrics
}

func New(log *slog.Logger) *Agent {
	server := strings.TrimRight(env("NETRA_SERVER", "http://netra.netra-system.svc:30870"), "/")
	client := &http.Client{Timeout: 10 * time.Second}
	wsDialer := *websocket.DefaultDialer
	// NETRA_CA_FILE trusts a private CA for the controller's certificate and
	// NETRA_CLIENT_CERT/NETRA_CLIENT_KEY present the agent's own (mutual TLS, see
	// docs/agent-mtls.md). With none of them set this is exactly the old behaviour.
	// A configured-but-unusable certificate is fatal, not a silent downgrade to an
	// agent the controller will then reject on every report.
	tlsCfg, tlsErr := mtls.ClientConfig(env("NETRA_CA_FILE", ""), env("NETRA_CLIENT_CERT", ""), env("NETRA_CLIENT_KEY", ""), envBool("NETRA_TLS_INSECURE", false))
	if tlsErr != nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12} // Run refuses to start; never used
	}
	if tlsCfg.InsecureSkipVerify || tlsCfg.RootCAs != nil || tlsCfg.GetClientCertificate != nil {
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
		wsDialer.TLSClientConfig = tlsCfg.Clone()
	}
	return &Agent{
		wsDialer: &wsDialer, tlsErr: tlsErr,
		log: log, server: server, key: os.Getenv("NETRA_AGENT_KEY"), node: env("NODE_NAME", hostname()), startedAt: time.Now().UTC(),
		object: env("NETRA_BPF_OBJECT", "/opt/netra/bpf/netra_tc.o"), pinPath: env("NETRA_BPF_PIN", "/sys/fs/bpf/netra"),
		edgeObject:      env("NETRA_BPF_EDGE_OBJECT", "/opt/netra/bpf/netra_edge_intel.o"),
		captureObject:   env("NETRA_BPF_CAPTURE_OBJECT", "/opt/netra/bpf/netra_capture.o"),
		tlsfpObject:     env("NETRA_BPF_TLSFP_OBJECT", "/opt/netra/bpf/netra_tlsfp.o"),
		tcpEventsObject: env("NETRA_BPF_TCPEVENTS_OBJECT", "/opt/netra/bpf/netra_tcpevents.o"),
		dropInfoObject:  env("NETRA_BPF_DROPINFO_OBJECT", "/opt/netra/bpf/netra_dropinfo.o"),
		nodeIsoObject:   env("NETRA_BPF_NODEISO_OBJECT", "/opt/netra/bpf/netra_nodeiso.o"),
		l7SampleObject:  env("NETRA_BPF_L7SAMPLE_OBJECT", "/opt/netra/bpf/netra_l7sample.o"),
		sslObject:       env("NETRA_BPF_SSL_OBJECT", "/opt/netra/bpf/netra_ssl.o"),
		cgroupPath:      env("NETRA_CGROUP_PATH", "/sys/fs/cgroup"), cgroupEnabled: envBool("NETRA_CGROUP_ENABLED", true),
		interfaces: splitCSV(os.Getenv("NETRA_INTERFACES")), xdpInterfaces: splitCSV(os.Getenv("NETRA_XDP_INTERFACES")),
		http: client, events: make(chan models.FastPathEvent, 4096), tlsFP: tlsfp.NewDetector(2048),
		failsafeAfter: envDuration("NETRA_FAILSAFE_AFTER", 60*time.Second), workloadByCgroup: map[uint64]models.WorkloadIdentity{}, cgroupScanEvery: envDuration("NETRA_CGROUP_SCAN_INTERVAL", 10*time.Second),
		procMetaEnabled: envBool("NETRA_PROCMETA_ENABLED", false),
		attachedProgs:   map[string]bool{},
		prevCaps:        map[uint64]uint64{},
		prevNetNS:       map[uint64]uint64{},
		prevExeHash:     map[uint64]string{},
	}
}

func (a *Agent) Run(ctx context.Context) error {
	if a.tlsErr != nil {
		return fmt.Errorf("agent TLS configuration: %w", a.tlsErr)
	}
	if err := a.loadAndAttach(); err != nil {
		return err
	}
	defer a.Close()
	if err := a.forceObserve(); err != nil {
		return fmt.Errorf("set startup observe mode: %w", err)
	}
	a.lastSync = time.Now()
	go a.readEvents(ctx)
	go a.readTLSHelloEvents(ctx)
	a.startNetlink(ctx)
	if a.netlinkWatch != nil {
		a.startRTNLActor(ctx, a.netlinkWatch)
	}
	a.startBPFAttach()
	a.startMetrics(ctx)
	if a.l7Sampler != nil {
		go a.l7Sampler.Run(ctx, a.l7Counters.Observe)
	}
	if a.sslProber != nil {
		go a.sslProber.Run(ctx, a.observeTLS)
		go a.rescanTLS(ctx)
	}
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			sweepProcessMetaCache()
			if !a.enforceUntil.IsZero() && !time.Now().Before(a.enforceUntil) {
				if err := a.forceObserve(); err != nil {
					a.log.Error("enforcement lease local expiry", "error", err)
				} else {
					a.lastRevision = 0
					a.log.Warn("enforcement lease expired locally; forced observe")
				}
			}
			if err := a.syncAndReport(ctx); err != nil {
				a.log.Warn("agent sync", "error", err)
				if a.failsafeAfter > 0 && time.Since(a.lastSync) >= a.failsafeAfter {
					if ferr := a.forceObserve(); ferr != nil {
						a.log.Error("eBPF failsafe observe", "error", ferr)
					} else {
						a.lastRevision = 0
						a.log.Warn("controller stale; forced Netra datapath to observe", "after", a.failsafeAfter.String())
					}
					a.applyNodeIsolation(a.nodeIsoSpec, "controller stale")
				}
			}
		}
	}
}

var mapNames = []string{
	"dest_stats", "flow_stats", "workload_flow_stats", "tcp_health", "tcp_pressure", "connect_health", "tcp_signals", "dns_pending", "dns_health", "tls_sni_stats", "http_host_stats", "http_status_stats", "connect_attempts", "socket_owner", "kernel_drops", "ipv6_ext_stats",
	"conntrack", "policy_drops", "shield_cfg", "shield_protected4", "shield_protected6", "shield_sources", "shield_stats", "netpol_deny4", "netpol_enabled",
	"netpol_rules4", "netpol_default4", "netpol_v2_enabled",
	"blocked_v4", "blocked_v6", "allowed_v4", "allowed_v6", "allowed_cidr_v4", "allowed_cidr_v6", "allowed_ports", "allowed_uids", "allowed_comms", "blocked_ingress_v4", "blocked_ingress_v6", "blocked_cidr_v4", "blocked_cidr_v6", "blocked_ports", "blocked_uids", "blocked_dns", "blocked_comms",
	"rate_v4", "rate_state_v4", "rate_v6", "rate_state_v6", "icmp_type_stats", "icmp6_type_stats", "blocked_sni", "config_map", "scope_config", "enforced_cgroups", "events",
	"shield_class_stats", "shield_source_hits", "iface_flow_stats", "icmp_errors", "udp_flow_health", "quic_observed",
	"conn_rate_limits", "conn_rate_state",
	"rate_bps_v4", "rate_byte_state_v4", "rate_bps_v6", "rate_byte_state_v6",
	"syndrop_v4", "syndrop_v6", "syndrop_cidr_v4", "syndrop_cidr_v6",
	"capgate_pids",
}

func (a *Agent) loadAndAttach() error {
	if err := os.MkdirAll(a.pinPath, 0o755); err != nil {
		return err
	}
	spec, err := ebpf.LoadCollectionSpec(a.object)
	if err != nil {
		return fmt.Errorf("load BPF ELF %s: %w", a.object, err)
	}
	repl := map[string]*ebpf.Map{}
	for _, name := range mapNames {
		if m, err := ebpf.LoadPinnedMap(filepath.Join(a.pinPath, name), nil); err == nil {
			repl[name] = m
			defer m.Close()
		}
	}
	l7Mode := strings.ToLower(env("NETRA_L7", "auto")) // auto|off|required
	l7Progs := []string{"netra_l7_cgroup_ingress", "netra_l7_cgroup_egress"}
	statusProgs := []string{"netra_http_status_ingress", "netra_http_status_egress"}
	l7Stripped := false
	if l7Mode == "off" {
		// Status programs share this object. Drop them too so a smoke that
		// turns L7 off does not pay the verifier cost, and does not attach.
		for _, p := range l7Progs {
			delete(spec.Programs, p)
		}
		for _, p := range statusProgs {
			delete(spec.Programs, p)
		}
		l7Stripped = true
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: repl})
	if err != nil && l7Mode == "auto" && (mentionsAny(err.Error(), l7Progs) || mentionsAny(err.Error(), statusProgs)) {
		// A kernel verifier rejection of one program fails the WHOLE
		// collection load, unlike an attach-time failure (handled below via
		// NETRA_L7's documented attach-with-fallback) which only affects that
		// one hook — the L7 cgroup programs' un-unrolled SNI/HTTP scan loops
		// are the ones known to vary in verifier acceptance across kernel
		// versions (see docs/l7-metadata.md). Drop the rejected programs and
		// retry so a rejection degrades rather than crash-looping the agent,
		// unless the operator has explicitly opted into NETRA_L7=required.
		a.log.Warn("L7/DNS or HTTP status programs failed verifier load; retrying without them", "error", err)
		if mentionsAny(err.Error(), l7Progs) {
			for _, p := range l7Progs {
				delete(spec.Programs, p)
			}
			l7Stripped = true
		}
		if mentionsAny(err.Error(), statusProgs) {
			for _, p := range statusProgs {
				delete(spec.Programs, p)
			}
		}
		coll, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: repl})
	}
	if err != nil {
		return fmt.Errorf("load BPF collection: %w", err)
	}
	a.collection = coll
	a.enableProgStats()
	for _, name := range mapNames {
		if m := coll.Maps[name]; m != nil {
			p := filepath.Join(a.pinPath, name)
			if _, err := os.Stat(p); os.IsNotExist(err) {
				if err := m.Pin(p); err != nil {
					a.log.Warn("pin map", "map", name, "error", err)
				}
			}
		}
	}
	if a.cgroupEnabled {
		for _, h := range []struct {
			name   string
			attach ebpf.AttachType
			prog   string
		}{
			{"cgroup-ingress", ebpf.AttachCGroupInetIngress, "netra_cgroup_ingress"},
			{"cgroup-egress", ebpf.AttachCGroupInetEgress, "netra_cgroup_egress"},
			{"connect4", ebpf.AttachCGroupInet4Connect, "netra_connect4"},
			{"connect6", ebpf.AttachCGroupInet6Connect, "netra_connect6"},
			{"udp-sendmsg4", ebpf.AttachCGroupUDP4Sendmsg, "netra_sendmsg4"},
			{"udp-sendmsg6", ebpf.AttachCGroupUDP6Sendmsg, "netra_sendmsg6"},
			{"sockops", ebpf.AttachCGroupSockOps, "netra_sockops"},
		} {
			p := coll.Programs[h.prog]
			if p == nil {
				return fmt.Errorf("BPF program %s missing", h.prog)
			}
			lnk, err := link.AttachCgroup(link.CgroupOptions{Path: a.cgroupPath, Attach: h.attach, Program: p})
			if err != nil {
				return fmt.Errorf("attach %s to %s: %w", h.name, a.cgroupPath, err)
			}
			a.links = append(a.links, lnk)
			a.hooks = append(a.hooks, h.name)
			a.markAttached(h.prog)
		}
		// L7/DNS (SNI/HTTP/DNS-qname) observability runs in its own dedicated
		// cgroup_skb programs, isolated from the CT/policy program's already-
		// tight verifier budget (see bpf/netra_tc.c and docs/l7-metadata.md).
		// NETRA_L7 mirrors NETRA_TCX's attach-with-fallback convention: real
		// kernel verifier acceptance for these programs' un-unrolled SNI/HTTP
		// scan loops can vary across kernel versions, so a rejection degrades
		// to "no L7 observability" rather than failing agent startup, unless
		// the operator has explicitly opted into NETRA_L7=required.
		if l7Mode != "off" && !l7Stripped {
			for _, h := range []struct {
				name   string
				attach ebpf.AttachType
				prog   string
			}{
				{"l7-cgroup-ingress", ebpf.AttachCGroupInetIngress, "netra_l7_cgroup_ingress"},
				{"l7-cgroup-egress", ebpf.AttachCGroupInetEgress, "netra_l7_cgroup_egress"},
			} {
				p := coll.Programs[h.prog]
				if p == nil {
					return fmt.Errorf("BPF program %s missing", h.prog)
				}
				lnk, err := link.AttachCgroup(link.CgroupOptions{Path: a.cgroupPath, Attach: h.attach, Program: p})
				if err != nil {
					if l7Mode == "required" {
						return fmt.Errorf("attach %s to %s (NETRA_L7=required): %w", h.name, a.cgroupPath, err)
					}
					a.log.Warn("L7/DNS cgroup program attach failed; continuing without L7 observability", "hook", h.name, "error", err)
					continue
				}
				a.links = append(a.links, lnk)
				a.hooks = append(a.hooks, h.name)
				a.markAttached(h.prog)
			}
		} else if l7Mode == "off" {
			a.log.Info("L7/DNS observability skipped by NETRA_L7=off")
		} else {
			a.log.Info("L7/DNS observability skipped: programs failed verifier load")
		}
		if l7Mode != "off" {
			for _, h := range []struct {
				name   string
				attach ebpf.AttachType
				prog   string
			}{
				{"http-status-ingress", ebpf.AttachCGroupInetIngress, "netra_http_status_ingress"},
				{"http-status-egress", ebpf.AttachCGroupInetEgress, "netra_http_status_egress"},
			} {
				p := coll.Programs[h.prog]
				if p == nil {
					a.log.Warn("HTTP/1 status program missing", "program", h.prog)
					continue
				}
				lnk, err := link.AttachCgroup(link.CgroupOptions{Path: a.cgroupPath, Attach: h.attach, Program: p})
				if err != nil {
					a.log.Warn("HTTP/1 status program attach failed", "hook", h.name, "error", err)
					continue
				}
				a.links = append(a.links, lnk)
				a.hooks = append(a.hooks, h.name)
				a.markAttached(h.prog)
			}
		}
	}
	// kfree_skb raw tracepoint is optional. Attach only when tracefs confirms
	// the modern drop-reason argument so older kernels cannot produce garbage.
	if p := coll.Programs["netra_kfree_skb"]; p != nil {
		if !kfreeDropReasonAvailable() {
			a.log.Warn("kernel drop reason tracepoint unavailable; using stack counters only", "tracepoint", "kfree_skb")
		} else {
			lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "kfree_skb", Program: p})
			if err != nil {
				a.log.Warn("kernel drop raw tracepoint unavailable", "tracepoint", "kfree_skb", "error", err)
			} else {
				a.links = append(a.links, lnk)
				a.hooks = append(a.hooks, "raw-tracepoint:kfree_skb")
				a.markAttached("netra_kfree_skb")
			}
		}
	}
	ifs, err := a.resolveInterfaces(a.interfaces)
	if err != nil {
		return err
	}
	a.interfaces = ifs
	tcxMode := strings.ToLower(env("NETRA_TCX", "auto")) // auto|off|required
	for _, name := range ifs {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("interface %s: %w", name, err)
		}
		if tcxMode == "off" {
			a.log.Info("TCX skipped by NETRA_TCX=off", "iface", name)
			continue
		}
		attached := 0
		for _, h := range []struct {
			name   string
			attach ebpf.AttachType
			prog   string
		}{{"tcx-ingress", ebpf.AttachTCXIngress, "netra_ingress"}, {"tcx-egress", ebpf.AttachTCXEgress, "netra_egress"}} {
			p := coll.Programs[h.prog]
			if p == nil {
				return fmt.Errorf("BPF program %s missing", h.prog)
			}
			lnk, err := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: p, Attach: h.attach})
			if err != nil {
				if tcxMode == "required" {
					return fmt.Errorf("attach %s to %s (NETRA_TCX=required): %w", h.name, name, err)
				}
				a.log.Warn("TCX attach failed; continuing without this hook", "hook", h.name, "iface", name, "error", err)
				continue
			}
			a.links = append(a.links, lnk)
			a.hooks = append(a.hooks, h.name+":"+name)
			a.markAttached(h.prog)
			attached++
		}
		if attached == 0 && tcxMode == "auto" {
			a.log.Warn("TCX unavailable on interface", "iface", name)
		}
	}
	if err := a.attachEdgeIntel(ifs); err != nil {
		return err
	}
	if err := a.attachCapture(ifs); err != nil {
		return err
	}
	if err := a.attachTLSFP(); err != nil {
		return err
	}
	if err := a.attachTCPEvents(); err != nil {
		return err
	}
	if err := a.attachDropInfo(); err != nil {
		return err
	}
	if err := a.attachNodeIsolation(ifs); err != nil {
		return err
	}
	a.attachListenQueues()
	if err := a.attachL7Sample(); err != nil {
		return err
	}
	if err := a.attachTLSUprobes(); err != nil {
		return err
	}
	xifs, err := a.resolveInterfaces(a.xdpInterfaces)
	if err != nil {
		return err
	}
	a.xdpInterfaces = xifs
	shieldProg := coll.Programs["netra_xdp_shield"]
	useShield := envBool("NETRA_XDP_SHIELD", false) && shieldProg != nil
	for _, name := range xifs {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("XDP interface %s: %w", name, err)
		}
		prog := coll.Programs["netra_xdp_ingress"]
		hook := "xdp:"
		if useShield {
			prog = shieldProg
			hook = "xdp-shield:"
		}
		if prog == nil {
			return fmt.Errorf("BPF XDP program missing")
		}
		lnk, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: iface.Index})
		if err != nil {
			return fmt.Errorf("attach XDP to %s: %w", name, err)
		}
		a.links = append(a.links, lnk)
		hookName := "netra_xdp_ingress"
		if useShield {
			hookName = "netra_xdp_shield"
		}
		a.hooks = append(a.hooks, hook+name)
		a.markAttached(hookName)
	}
	sort.Strings(a.hooks)
	a.log.Info("Netra standalone datapath attached", "cgroup", a.cgroupEnabled, "cgroupPath", a.cgroupPath, "interfaces", a.interfaces, "xdpInterfaces", a.xdpInterfaces, "hooks", a.hooks)
	return nil
}

func kfreeDropReasonAvailable() bool {
	for _, p := range []string{
		"/sys/kernel/tracing/events/skb/kfree_skb/format",
		"/sys/kernel/debug/tracing/events/skb/kfree_skb/format",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		text := string(b)
		if strings.Contains(text, "skb_drop_reason") && strings.Contains(text, "reason") {
			return true
		}
	}
	return false
}

// edgeIntelMapNames are edge_tcp_intel's own pinned maps — a separate
// pin namespace from mapNames (the main object's maps), same pinPath
// directory. Pinning follows the same upgrade-in-place convention as
// every other map in this agent: counters/histograms survive an agent
// restart instead of resetting to zero.
var edgeIntelMapNames = []string{"edge_tcp_flows", "edge_tcp_hist", "edge_tcp_counts"}

// attachEdgeIntel loads and attaches the standalone edge-TCP-intel BPF
// object (bpf/netra_edge_intel.c) as a second TCX program pair on every
// interface already resolved for the main netra_ingress/egress attach —
// see that function's doc comment for why this is a separate object
// rather than a branch inside bpf/netra_tc.c. Mirrors NETRA_TCX/NETRA_L7's
// auto|off|required attach-with-fallback convention exactly (env var
// NETRA_EDGE_INTEL) so a rejection on some kernel degrades to "no edge
// intel" rather than failing agent startup, unless the operator has
// explicitly opted into NETRA_EDGE_INTEL=required. Unlike the main
// object, a missing/unreadable object FILE (not yet built into this
// image, or deliberately absent) is also tolerated in auto mode — this is
// a newer, optional feature, not a load-bearing one.
func (a *Agent) attachEdgeIntel(ifs []string) error {
	mode := strings.ToLower(env("NETRA_EDGE_INTEL", "auto")) // auto|off|required
	if mode == "off" {
		a.log.Info("edge TCP intel skipped by NETRA_EDGE_INTEL=off")
		return nil
	}
	spec, err := ebpf.LoadCollectionSpec(a.edgeObject)
	if err != nil {
		if mode == "required" {
			return fmt.Errorf("load BPF ELF %s (NETRA_EDGE_INTEL=required): %w", a.edgeObject, err)
		}
		a.log.Warn("edge TCP intel object unavailable; continuing without it", "object", a.edgeObject, "error", err)
		return nil
	}
	repl := map[string]*ebpf.Map{}
	for _, name := range edgeIntelMapNames {
		if m, err := ebpf.LoadPinnedMap(filepath.Join(a.pinPath, name), nil); err == nil {
			repl[name] = m
			defer m.Close()
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: repl})
	if err != nil {
		if mode == "required" {
			return fmt.Errorf("load edge TCP intel BPF collection (NETRA_EDGE_INTEL=required): %w", err)
		}
		a.log.Warn("edge TCP intel BPF collection failed to load; continuing without it", "error", err)
		return nil
	}
	a.edgeCollection = coll
	for _, name := range edgeIntelMapNames {
		if m := coll.Maps[name]; m != nil {
			p := filepath.Join(a.pinPath, name)
			if _, err := os.Stat(p); os.IsNotExist(err) {
				if err := m.Pin(p); err != nil {
					a.log.Warn("pin map", "map", name, "error", err)
				}
			}
		}
	}
	for _, name := range ifs {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			if mode == "required" {
				return fmt.Errorf("interface %s (NETRA_EDGE_INTEL=required): %w", name, err)
			}
			a.log.Warn("edge TCP intel interface lookup failed; skipping", "iface", name, "error", err)
			continue
		}
		for _, h := range []struct {
			name   string
			attach ebpf.AttachType
			prog   string
		}{{"edge-tcx-ingress", ebpf.AttachTCXIngress, "netra_edge_ingress"}, {"edge-tcx-egress", ebpf.AttachTCXEgress, "netra_edge_egress"}} {
			p := coll.Programs[h.prog]
			if p == nil {
				if mode == "required" {
					return fmt.Errorf("BPF program %s missing (NETRA_EDGE_INTEL=required)", h.prog)
				}
				a.log.Warn("edge TCP intel program missing; skipping", "program", h.prog)
				continue
			}
			// A second, independent TCX program on the same interface+
			// direction as netra_ingress/egress — TCX supports chaining
			// multiple programs per attach point (unlike classic TC),
			// confirmed via bpftool net show as part of live verification,
			// not assumed from documentation alone.
			//
			// Anchor: link.Head() is required, not cosmetic. TCX's mprog
			// chain short-circuits on any verdict other than TCX_NEXT
			// (which is numerically TC_ACT_UNSPEC, -1) — netra_ingress/
			// egress return TC_ACT_OK for allowed traffic, a definite
			// verdict that terminates the chain right there. A program
			// attached *after* them (the default, tail-appended position)
			// would then never run for any already-decided packet —
			// confirmed live: with a tail attach, edge_tcp_counts/_hist
			// stayed empty under real traffic despite both TCX links
			// showing attached in bpftool net show. Head() makes this
			// program run first, before any other program on the hook has
			// rendered a verdict, so its own always-TC_ACT_UNSPEC return
			// never blocks the chain and it never misses a packet.
			lnk, err := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: p, Attach: h.attach, Anchor: link.Head()})
			if err != nil {
				if mode == "required" {
					return fmt.Errorf("attach %s to %s (NETRA_EDGE_INTEL=required): %w", h.name, name, err)
				}
				a.log.Warn("edge TCP intel TCX attach failed; continuing without this hook", "hook", h.name, "iface", name, "error", err)
				continue
			}
			a.links = append(a.links, lnk)
			a.hooks = append(a.hooks, h.name+":"+name)
		}
	}
	return nil
}

var captureMapNames = []string{"capture_spec", "capture_rate", "capture_events"}

// attachCapture loads and attaches the standalone packet-capture BPF object
// (bpf/netra_capture.c) as a fourth TCX program pair, mirroring
// attachEdgeIntel above exactly (same auto|off|required convention via
// NETRA_CAPTURE, same tolerance for a missing object file in auto mode —
// this is an optional, newer sensor, not load-bearing). See that function's
// doc comment and bpf/netra_capture.c's own header comment for why this
// stays a separate object rather than a branch inside bpf/netra_tc.c: a bug
// here can never affect a packet's verdict, only whether it gets captured.
func (a *Agent) attachCapture(ifs []string) error {
	mode := strings.ToLower(env("NETRA_CAPTURE", "auto")) // auto|off|required
	if mode == "off" {
		a.log.Info("packet capture skipped by NETRA_CAPTURE=off")
		return nil
	}
	spec, err := ebpf.LoadCollectionSpec(a.captureObject)
	if err != nil {
		if mode == "required" {
			return fmt.Errorf("load BPF ELF %s (NETRA_CAPTURE=required): %w", a.captureObject, err)
		}
		a.log.Warn("packet capture object unavailable; continuing without it", "object", a.captureObject, "error", err)
		return nil
	}
	repl := map[string]*ebpf.Map{}
	for _, name := range captureMapNames {
		if m, err := ebpf.LoadPinnedMap(filepath.Join(a.pinPath, name), nil); err == nil {
			repl[name] = m
			defer m.Close()
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: repl})
	if err != nil {
		if mode == "required" {
			return fmt.Errorf("load packet capture BPF collection (NETRA_CAPTURE=required): %w", err)
		}
		a.log.Warn("packet capture BPF collection failed to load; continuing without it", "error", err)
		return nil
	}
	a.captureCollection = coll
	for _, name := range captureMapNames {
		if m := coll.Maps[name]; m != nil {
			p := filepath.Join(a.pinPath, name)
			if _, err := os.Stat(p); os.IsNotExist(err) {
				if err := m.Pin(p); err != nil {
					a.log.Warn("pin map", "map", name, "error", err)
				}
			}
		}
	}
	for _, name := range ifs {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			if mode == "required" {
				return fmt.Errorf("interface %s (NETRA_CAPTURE=required): %w", name, err)
			}
			a.log.Warn("packet capture interface lookup failed; skipping", "iface", name, "error", err)
			continue
		}
		for _, h := range []struct {
			name   string
			attach ebpf.AttachType
			prog   string
		}{{"capture-tcx-ingress", ebpf.AttachTCXIngress, "netra_capture_ingress"}, {"capture-tcx-egress", ebpf.AttachTCXEgress, "netra_capture_egress"}} {
			p := coll.Programs[h.prog]
			if p == nil {
				if mode == "required" {
					return fmt.Errorf("BPF program %s missing (NETRA_CAPTURE=required)", h.prog)
				}
				a.log.Warn("packet capture program missing; skipping", "program", h.prog)
				continue
			}
			lnk, err := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: p, Attach: h.attach, Anchor: link.Head()})
			if err != nil {
				if mode == "required" {
					return fmt.Errorf("attach %s to %s (NETRA_CAPTURE=required): %w", h.name, name, err)
				}
				a.log.Warn("packet capture TCX attach failed; continuing without this hook", "hook", h.name, "iface", name, "error", err)
				continue
			}
			a.links = append(a.links, lnk)
			a.hooks = append(a.hooks, h.name+":"+name)
		}
	}
	return nil
}

var tlsfpMapNames = []string{"tls_hello_events", "tls_hello_rate"}

// attachTLSFP loads bpf/netra_tlsfp.c — continuous ClientHello sampling with
// its own verifier budget (works even when netra_l7_* is rejected).
func (a *Agent) attachTLSFP() error {
	if !a.cgroupEnabled {
		return nil
	}
	mode := strings.ToLower(env("NETRA_TLSFP", "auto")) // auto|off|required
	if mode == "off" {
		a.log.Info("TLS fingerprint sampler skipped by NETRA_TLSFP=off")
		return nil
	}
	spec, err := ebpf.LoadCollectionSpec(a.tlsfpObject)
	if err != nil {
		if mode == "required" {
			return fmt.Errorf("load BPF ELF %s (NETRA_TLSFP=required): %w", a.tlsfpObject, err)
		}
		a.log.Warn("TLS fingerprint object unavailable; continuing without datapath JA3", "object", a.tlsfpObject, "error", err)
		return nil
	}
	repl := map[string]*ebpf.Map{}
	for _, name := range tlsfpMapNames {
		if m, err := ebpf.LoadPinnedMap(filepath.Join(a.pinPath, name), nil); err == nil {
			repl[name] = m
			defer m.Close()
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: repl})
	if err != nil {
		if mode == "required" {
			return fmt.Errorf("load TLS fingerprint BPF collection (NETRA_TLSFP=required): %w", err)
		}
		a.log.Warn("TLS fingerprint BPF collection failed to load; continuing without datapath JA3", "error", err)
		return nil
	}
	a.tlsfpCollection = coll
	for _, name := range tlsfpMapNames {
		if m := coll.Maps[name]; m != nil {
			p := filepath.Join(a.pinPath, name)
			if _, err := os.Stat(p); os.IsNotExist(err) {
				if err := m.Pin(p); err != nil {
					a.log.Warn("pin map", "map", name, "error", err)
				}
			}
		}
	}
	p := coll.Programs["netra_tlsfp_egress"]
	if p == nil {
		if mode == "required" {
			return fmt.Errorf("BPF program netra_tlsfp_egress missing (NETRA_TLSFP=required)")
		}
		a.log.Warn("TLS fingerprint program missing; continuing without datapath JA3")
		return nil
	}
	lnk, err := link.AttachCgroup(link.CgroupOptions{Path: a.cgroupPath, Attach: ebpf.AttachCGroupInetEgress, Program: p})
	if err != nil {
		if mode == "required" {
			return fmt.Errorf("attach netra_tlsfp_egress (NETRA_TLSFP=required): %w", err)
		}
		a.log.Warn("TLS fingerprint cgroup attach failed; continuing without datapath JA3", "error", err)
		return nil
	}
	a.links = append(a.links, lnk)
	a.hooks = append(a.hooks, "tlsfp-cgroup-egress")
	a.markAttached("netra_tlsfp_egress")
	a.log.Info("TLS fingerprint sampler attached", "object", a.tlsfpObject)
	return nil
}

// edgeHistKey/edgeHistValue/edgeCountKey mirror bpf/netra_edge_intel.c's
// struct edge_hist_key/edge_hist_value/edge_count_key byte-for-byte —
// cilium/ebpf decodes map entries directly into these via reflection, the
// same convention every other typed map read in this file already uses.
type edgeHistKey struct{ Kind, Bucket uint32 }
type edgeHistValue struct{ Count, TotalNS, MaxNS uint64 }
type edgeCountKey struct{ Kind uint32 }

// edgeCountNames maps bpf/netra_edge_intel.c's EDGE_COUNT_* constants to
// the JSON keys models.EdgeIntelSummary.Counts uses.
var edgeCountNames = map[uint32]string{
	1: "syn", 2: "established", 3: "retransmit", 4: "rst", 5: "fin", 6: "flowMiss",
}

// readEdgeIntel returns nil when edge TCP intel never attached
// (a.edgeCollection is nil — NETRA_EDGE_INTEL=off, or auto-mode attach
// failure) — see models.EdgeIntelSummary's doc comment on why that's
// distinct from an attached-but-quiet node.
func (a *Agent) readEdgeIntel() (*models.EdgeIntelSummary, error) {
	if a.edgeCollection == nil {
		return nil, nil
	}
	out := &models.EdgeIntelSummary{Counts: map[string]uint64{}}
	if m := a.edgeCollection.Maps["edge_tcp_hist"]; m != nil {
		var k edgeHistKey
		var v edgeHistValue
		it := m.Iterate()
		for it.Next(&k, &v) {
			bucket := models.EdgeIntelBucket{Count: v.Count, TotalNS: v.TotalNS, MaxNS: v.MaxNS}
			var target *[]models.EdgeIntelBucket
			switch k.Kind {
			case 1: // EDGE_HIST_HANDSHAKE
				target = &out.Handshake
			case 2: // EDGE_HIST_RTT
				target = &out.RTT
			default:
				continue
			}
			for len(*target) <= int(k.Bucket) {
				*target = append(*target, models.EdgeIntelBucket{})
			}
			(*target)[k.Bucket] = bucket
		}
		if err := mapIterErr(it.Err()); err != nil {
			return nil, err
		}
	}
	if m := a.edgeCollection.Maps["edge_tcp_counts"]; m != nil {
		var k edgeCountKey
		var v uint64
		it := m.Iterate()
		for it.Next(&k, &v) {
			if name, ok := edgeCountNames[k.Kind]; ok {
				out.Counts[name] = v
			}
		}
		if err := mapIterErr(it.Err()); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (a *Agent) resolveInterfaces(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) == 1 && strings.EqualFold(in[0], "auto") {
		all, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(all))
		for _, it := range all {
			if it.Flags&net.FlagLoopback != 0 || it.Flags&net.FlagUp == 0 {
				continue
			}
			out = append(out, it.Name)
		}
		sort.Strings(out)
		return out, nil
	}
	return in, nil
}

func (a *Agent) Close() {
	a.stopCaptureStream()
	for _, l := range a.links {
		_ = l.Close()
	}
	if a.progStats != nil {
		_ = a.progStats.Close()
		a.progStats = nil
	}
	if a.collection != nil {
		a.collection.Close()
	}
	if a.edgeCollection != nil {
		a.edgeCollection.Close()
	}
	if a.captureCollection != nil {
		a.captureCollection.Close()
	}
	if a.tlsfpCollection != nil {
		a.tlsfpCollection.Close()
	}
	if a.tcpEvents != nil {
		_ = a.tcpEvents.Close()
		a.tcpEvents = nil
	}
	if a.dropInfo != nil {
		_ = a.dropInfo.Close()
		a.dropInfo = nil
	}
	if a.nodeIso != nil {
		_ = a.nodeIso.Close()
		a.nodeIso = nil
	}
	if a.l7Sampler != nil {
		_ = a.l7Sampler.Close()
		a.l7Sampler = nil
	}
	if a.sslProber != nil {
		_ = a.sslProber.Close()
		a.sslProber = nil
	}
	_ = a.rtnlSensor.Close()
	a.rtnlSensor = nil
	a.netlinkWatch.Close()
	a.netlinkWatch = nil
}

func (a *Agent) syncAndReport(ctx context.Context) error {
	cfg, err := a.fetchConfig(ctx)
	if err != nil {
		return err
	}
	if cfg.Revision != a.lastRevision {
		if err := a.applyConfig(cfg); err != nil {
			return err
		}
		a.lastRevision = cfg.Revision
	}
	if err := a.applyWorkloadScopes(cfg); err != nil {
		return err
	}
	if err := a.applyNetPolV2(cfg); err != nil {
		return err
	}
	if err := a.applyConnRateLimits(cfg); err != nil {
		return err
	}
	// Capture is reconciled unconditionally on every tick, not gated by
	// cfg.Revision — a capture session is per-node operator state, not
	// part of the cluster-wide firewall config revision, and needs to
	// start/stop within one 3s tick regardless of whether anything else
	// changed. Failure here is logged, not fatal: a broken capture session
	// must never take down the rest of the report/sync cycle.
	if err := a.applyCapture(ctx, cfg.DesiredCapture); err != nil {
		a.log.Warn("apply capture", "error", err)
	}
	// Node isolation is per-node operator state like capture: reconciled
	// every tick, and a failure never stops the report.
	a.applyNodeIsolation(cfg.NodeIsolation, "")
	a.lastSync = time.Now()
	stats, err := a.readStats()
	if err != nil {
		return err
	}
	tcpHealth, err := a.readTCPHealth()
	if err != nil {
		return err
	}
	processMeta := a.readProcessMeta(pidsFromTCPHealth(tcpHealth))
	a.enrichSocketOwnership(tcpHealth, processMeta)
	capChanges := a.watchCapChanges(processMeta, cgroupsByPID(tcpHealth))
	namespaceChanges := a.watchNamespaceChanges(processMeta, cgroupsByPID(tcpHealth))
	exeHashChanges := a.watchExeHashChanges(processMeta, cgroupsByPID(tcpHealth))
	tcpPressure, err := a.readTCPPressure()
	if err != nil {
		return err
	}
	connectLatency, err := a.readConnectLatency()
	if err != nil {
		return err
	}
	tcpSignals, err := a.readTCPSignals()
	if err != nil {
		return err
	}
	dnsHealth, err := a.readDNSHealth()
	if err != nil {
		return err
	}
	tlsMeta, err := a.readTLSMetadata()
	if err != nil {
		return err
	}
	httpMeta, err := a.readHTTPMetadata()
	if err != nil {
		return err
	}
	httpStatus, err := a.readHTTPStatus()
	if err != nil {
		return err
	}
	connAttempts, err := a.readConnectionAttempts()
	if err != nil {
		return err
	}
	kernelDrops, err := a.readKernelDrops()
	if err != nil {
		return err
	}
	icmpTypes, err := a.readICMPTypeStats("icmp_type_stats")
	if err != nil {
		return err
	}
	icmp6Types, err := a.readICMPTypeStats("icmp6_type_stats")
	if err != nil {
		return err
	}
	rateDrops, err := a.readRateDrops()
	if err != nil {
		return err
	}
	byteRateDrops, err := a.readByteRateDrops()
	if err != nil {
		return err
	}
	connRateDrops, err := a.readConnRateDrops()
	if err != nil {
		return err
	}
	icmpErrors, err := a.readICMPErrors()
	if err != nil {
		return err
	}
	ipv6ExtHeaders, err := a.readIPv6ExtStats()
	if err != nil {
		return err
	}
	policyDrops, err := a.readPolicyDrops()
	if err != nil {
		return err
	}
	policyDrops = a.attributePolicyDrops(policyDrops, tcpHealth)
	ctEntries, err := a.countEntries("conntrack")
	if err != nil {
		return err
	}
	shieldStats, err := a.readShieldStats()
	if err != nil {
		return err
	}
	shieldClasses, err := a.readShieldClassStats()
	if err != nil {
		return err
	}
	shieldSources, err := a.readShieldSourceHits()
	if err != nil {
		return err
	}
	ifaceFlows, err := a.readInterfaceFlowStats()
	if err != nil {
		return err
	}
	udpFlowHealth, err := a.readUDPFlowHealth()
	if err != nil {
		return err
	}
	quicObserved, err := a.readQUICObserved()
	if err != nil {
		return err
	}
	stack := a.readNodeStack()
	qdiscStats := a.readQdiscStats()
	kernelNetwork := kerneldiag.Collect("/")
	sysctlAudit := sysctlaudit.Collect("/")
	nodeResources, hostProcesses := a.readNodeResources()
	histReport := histograms.FromAgentSamples(tcpHealth, connectLatency, a.readHostHistogramCounters())
	histJSON := models.NetworkHistogramReport{
		TCPRetransmissions: models.HistogramSnapshot{
			Name: histReport.TCPRetransmissions.Name, Bounds: histReport.TCPRetransmissions.Bounds,
			CumulativeCounts: histReport.TCPRetransmissions.CumulativeCounts, Sum: histReport.TCPRetransmissions.Sum, Count: histReport.TCPRetransmissions.Count,
		},
		TCPSRTTUS: models.HistogramSnapshot{
			Name: histReport.TCPSRTTUS.Name, Bounds: histReport.TCPSRTTUS.Bounds,
			CumulativeCounts: histReport.TCPSRTTUS.CumulativeCounts, Sum: histReport.TCPSRTTUS.Sum, Count: histReport.TCPSRTTUS.Count,
		},
		TCPConnectUS: models.HistogramSnapshot{
			Name: histReport.TCPConnectUS.Name, Bounds: histReport.TCPConnectUS.Bounds,
			CumulativeCounts: histReport.TCPConnectUS.CumulativeCounts, Sum: histReport.TCPConnectUS.Sum, Count: histReport.TCPConnectUS.Count,
		},
		Host: models.NetworkHostCounters{
			ListenOverflows: histReport.Host.ListenOverflows,
			ListenDrops:     histReport.Host.ListenDrops,
			SoftirqNETRX:    histReport.Host.SoftirqNETRX,
		},
	}
	programs := a.readProgramHealth()
	events := a.drainEvents(500)
	edgeIntel, err := a.readEdgeIntel()
	if err != nil {
		return err
	}
	tcpEvents := a.readTCPEvents()
	nodeIsolation := a.readNodeIsolation()
	dropInfo := a.readDropInfo()
	listenQueues := a.readListenQueues()
	l7 := a.readL7Sample()
	tlsSample := a.readTLSSample()
	netlinkReport, commitNetlink := a.readNetlink()
	bpfAttachReport, commitBPFAttach := a.readBPFAttach(time.Now().UTC())
	rep := models.AgentReport{
		Node: a.node, Mode: cfg.Mode, Interfaces: a.interfaces, XDPInterfaces: a.xdpInterfaces,
		Hooks: append([]string(nil), a.hooks...), CgroupPath: a.cgroupPath, Standalone: true,
		Stats: stats, TCPHealth: tcpHealth, TCPPressure: tcpPressure, ConnectLatency: connectLatency,
		TCPSignals: tcpSignals, DNSHealth: dnsHealth, TLSMetadata: tlsMeta, TLSFingerprints: a.drainTLSFingerprints(200), HTTPMetadata: httpMeta, HTTPStatus: httpStatus,
		ConnectionAttempts: connAttempts, KernelDrops: kernelDrops, ICMPTypes: icmpTypes, ICMP6Types: icmp6Types, RateDrops: rateDrops, ByteRateDrops: byteRateDrops, ConnRateDrops: connRateDrops, MissingMaps: a.missingMaps(), ICMPErrors: icmpErrors, IPv6ExtHeaders: ipv6ExtHeaders, PolicyDrops: policyDrops,
		ConntrackEntries: ctEntries, Shield: shieldStats, ShieldClasses: shieldClasses, ShieldSources: shieldSources, InterfaceFlows: ifaceFlows, UDPFlowHealth: udpFlowHealth, QUICObserved: quicObserved, ProcessMeta: processMeta,
		Programs: programs, Histograms: &histJSON, EdgeIntel: edgeIntel, TCPEvents: tcpEvents, NodeIsolation: nodeIsolation, DropInfo: dropInfo, ListenQueues: listenQueues, L7Sample: l7, TLSSample: tlsSample, MapScans: a.mapScans(), CapChanges: capChanges, NamespaceChanges: namespaceChanges, ExeHashChanges: exeHashChanges, AgentStartedAt: a.startedAt,
		Stack: stack, Events: events, ObservedAt: time.Now().UTC(),
		Workloads: a.workloadSnapshot(), ScopeMode: a.scopeMode, SelectedCgroups: a.selectedCgroups,
		QdiscStats:         qdiscStats,
		Netlink:            netlinkReport,
		BPFAttach:          bpfAttachReport,
		KernelNetwork:      kernelNetwork,
		SysctlNetworkAudit: sysctlAudit,
		NodeResources:      nodeResources,
		HostProcesses:      hostProcesses,
		StackSamples:       stackSamplesFor(a.node, hostProcesses),
		KernelNotes:        kernelNotes(a.node),
	}
	a.metrics.setLatest(&rep)
	if err := a.report(ctx, rep); err != nil {
		return err
	}
	commitNetlink()
	commitBPFAttach()
	return nil
}

func stackSamplesFor(node string, tops models.HostProcessTops) []models.StackSample {
	samples := sysres.SampleStacks("/", tops, 5, 16)
	for i := range samples {
		samples[i].Node = node
	}
	return samples
}

// pidsFromTCPHealth collects the unique nonzero PIDs observed in the
// current TCP health snapshot — the richest available source of
// currently-relevant process identity — for procmeta enrichment.
func pidsFromTCPHealth(stats []models.TCPHealthStat) []uint32 {
	seen := map[uint32]struct{}{}
	var out []uint32
	for _, t := range stats {
		if t.PID == 0 {
			continue
		}
		if _, ok := seen[t.PID]; ok {
			continue
		}
		seen[t.PID] = struct{}{}
		out = append(out, t.PID)
	}
	return out
}

// cgroupsByPID maps PID -> CgroupID from the current TCP health snapshot,
// for watchCapChanges to attribute a capability-change event to a workload
// without a second lookup mechanism (see its doc comment).
func cgroupsByPID(stats []models.TCPHealthStat) map[uint32]uint64 {
	out := make(map[uint32]uint64, len(stats))
	for _, t := range stats {
		if t.PID == 0 || t.CgroupID == 0 {
			continue
		}
		out[t.PID] = t.CgroupID
	}
	return out
}
func (a *Agent) fetchConfig(ctx context.Context) (models.EBPFFastPathConfig, error) {
	var cfg models.EBPFFastPathConfig
	req, _ := http.NewRequestWithContext(ctx, "GET", a.server+"/api/v1/ebpf/config?node="+url.QueryEscape(a.node), nil)
	if a.key != "" {
		req.Header.Set("X-Netra-Agent-Key", a.key)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return cfg, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return cfg, fmt.Errorf("config: %s %s", resp.Status, b)
	}
	err = json.NewDecoder(resp.Body).Decode(&cfg)
	return cfg, err
}
func (a *Agent) forceObserve() error {
	a.enforceUntil = time.Time{}
	if a.collection == nil || a.collection.Maps["config_map"] == nil {
		return fmt.Errorf("config_map unavailable")
	}
	return a.collection.Maps["config_map"].Put(uint32(0), uint32(0))
}

func (a *Agent) applyConfig(cfg models.EBPFFastPathConfig) error {
	a.enforceUntil = time.Time{}
	if cfg.Mode == "enforce" && cfg.EnforceUntil != nil {
		a.enforceUntil = cfg.EnforceUntil.UTC()
	}
	mode := uint32(0)
	if cfg.Mode == "enforce" {
		mode = 1
	}
	if err := a.collection.Maps["config_map"].Put(uint32(0), mode); err != nil {
		return err
	}
	if err := a.replaceIPSet("blocked_v4", cfg.BlockedIPv4, 4); err != nil {
		return err
	}
	if err := a.replaceIPSet("blocked_v6", cfg.BlockedIPv6, 16); err != nil {
		return err
	}
	if err := a.replaceIPSet("allowed_v4", cfg.AllowedIPv4, 4); err != nil {
		return err
	}
	if err := a.replaceIPSet("allowed_v6", cfg.AllowedIPv6, 16); err != nil {
		return err
	}
	if err := a.replaceIPSet("blocked_ingress_v4", cfg.BlockedIngressIPv4, 4); err != nil {
		return err
	}
	if err := a.replaceIPSet("blocked_ingress_v6", cfg.BlockedIngressIPv6, 16); err != nil {
		return err
	}
	if err := a.replaceAllowedCIDRs(cfg.AllowedCIDRs); err != nil {
		return err
	}
	if err := a.replaceCIDRs(cfg.BlockedCIDRs); err != nil {
		return err
	}
	if err := a.applySynDrop(cfg.SynDrop); err != nil {
		return err
	}
	if err := a.applySynDropCIDR(cfg.SynDropCIDR); err != nil {
		return err
	}
	if err := a.applyCapabilityGate(cfg); err != nil {
		return err
	}
	if err := a.replacePorts(cfg.BlockedPorts); err != nil {
		return err
	}
	if err := a.replacePortMap("allowed_ports", cfg.AllowedPorts); err != nil {
		return err
	}
	if err := a.replaceUIDs(cfg.BlockedUIDs); err != nil {
		return err
	}
	if err := a.replaceUIDMap("allowed_uids", cfg.AllowedUIDs); err != nil {
		return err
	}
	if err := a.replaceStringMap("blocked_dns", cfg.BlockedDNS, 96); err != nil {
		return err
	}
	if err := a.replaceStringMap("blocked_comms", cfg.BlockedProcesses, 16); err != nil {
		return err
	}
	if err := a.replaceStringMap("allowed_comms", cfg.AllowedProcesses, 16); err != nil {
		return err
	}
	if err := a.replaceStringMap("blocked_sni", cfg.BlockedSNI, 96); err != nil {
		return err
	}
	if err := a.replaceRates(cfg.RateLimits); err != nil {
		return err
	}
	if err := a.replaceByteRates(cfg.RateLimits); err != nil {
		return err
	}
	if err := a.applyShield(cfg.Shield); err != nil {
		return err
	}
	if err := a.applyNetPol(cfg); err != nil {
		return err
	}
	return nil
}
func (a *Agent) replaceIPSet(name string, values []string, size int) error {
	m := a.collection.Maps[name]
	if m == nil {
		return fmt.Errorf("map %s unavailable", name)
	}
	if size == 4 {
		var k [4]byte
		var v uint8
		var keys [][4]byte
		it := m.Iterate()
		for it.Next(&k, &v) {
			keys = append(keys, k)
		}
		for _, x := range keys {
			_ = m.Delete(x)
		}
		if err := mapIterErr(it.Err()); err != nil {
			return err
		}
		for _, s := range values {
			ip := net.ParseIP(s)
			if ip == nil || ip.To4() == nil {
				continue
			}
			var q [4]byte
			copy(q[:], ip.To4())
			if err := m.Put(q, uint8(1)); err != nil {
				return err
			}
		}
		return nil
	}
	var k [16]byte
	var v uint8
	var keys [][16]byte
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = m.Delete(x)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return err
	}
	for _, s := range values {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() != nil {
			continue
		}
		var q [16]byte
		copy(q[:], ip.To16())
		if err := m.Put(q, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}
func dirs(s string) []byte {
	switch strings.ToLower(s) {
	case "ingress":
		return []byte{1}
	case "both":
		return []byte{1, 2}
	default:
		return []byte{2}
	}
}

// applySynDrop clears and rewrites syndrop_v4/v6 from cfg.SynDrop — same
// full clear-then-rewrite convention as replaceCIDRMaps. Key layout
// matches struct syndrop_key4/syndrop_key6 in bpf/netra_tc.c: address
// bytes (network order, same raw copy replaceIPSet already uses for
// blocked_v4/v6), then a 1-byte direction (1=ingress, 2=egress, matching
// dirs()), then zero-padding — direction is always exactly one value here
// (validated server-side to be "egress" or "ingress", never "both"), so
// dirs()[0] is always safe.
func (a *Agent) applySynDrop(entries []models.EBPFSynDropEntry) error {
	m4 := a.collection.Maps["syndrop_v4"]
	if m4 == nil {
		return fmt.Errorf("map syndrop_v4 unavailable")
	}
	m6 := a.collection.Maps["syndrop_v6"]
	if m6 == nil {
		return fmt.Errorf("map syndrop_v6 unavailable")
	}
	var k4 [8]byte
	var k6 [20]byte
	var v uint8
	var ks4 [][8]byte
	var ks6 [][20]byte
	i4 := m4.Iterate()
	for i4.Next(&k4, &v) {
		ks4 = append(ks4, k4)
	}
	for _, k := range ks4 {
		_ = m4.Delete(k)
	}
	if err := mapIterErr(i4.Err()); err != nil {
		return err
	}
	i6 := m6.Iterate()
	for i6.Next(&k6, &v) {
		ks6 = append(ks6, k6)
	}
	for _, k := range ks6 {
		_ = m6.Delete(k)
	}
	if err := mapIterErr(i6.Err()); err != nil {
		return err
	}
	for _, e := range entries {
		ip := net.ParseIP(e.Address)
		if ip == nil {
			continue
		}
		d := dirs(e.Direction)[0]
		if v4 := ip.To4(); v4 != nil {
			var k [8]byte
			copy(k[0:4], v4)
			k[4] = d
			if err := m4.Put(k, uint8(1)); err != nil {
				return err
			}
			continue
		}
		var k [20]byte
		copy(k[0:16], ip.To16())
		k[16] = d
		if err := m6.Put(k, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) replaceCIDRs(rules []models.EBPFCIDRRule) error {
	return a.replaceCIDRMaps(a.collection.Maps["blocked_cidr_v4"], a.collection.Maps["blocked_cidr_v6"], rules)
}

// applySynDropCIDR clears and rewrites syndrop_cidr_v4/v6 from
// cfg.SynDropCIDR, reusing replaceCIDRMaps unchanged — the key layout is
// identical to blocked_cidr_v4/v6 (see struct lpm4_key/lpm6_key in
// bpf/netra_tc.c), so the same LPM-trie writer applies. EBPFSynDropCIDR is
// converted to EBPFCIDRRule's shape only because replaceCIDRMaps is typed
// against it; Direction is still only ever "egress"/"ingress" here
// (validated server-side), never "both".
func (a *Agent) applySynDropCIDR(entries []models.EBPFSynDropCIDR) error {
	rules := make([]models.EBPFCIDRRule, len(entries))
	for i, e := range entries {
		rules[i] = models.EBPFCIDRRule{CIDR: e.CIDR, Direction: e.Direction}
	}
	return a.replaceCIDRMaps(a.collection.Maps["syndrop_cidr_v4"], a.collection.Maps["syndrop_cidr_v6"], rules)
}

func (a *Agent) replaceCIDRMaps(m4, m6 *ebpf.Map, rules []models.EBPFCIDRRule) error {
	if m4 == nil || m6 == nil {
		return fmt.Errorf("cidr maps unavailable")
	}
	var k4 [9]byte
	var k6 [21]byte
	var v uint8
	var ks4 [][9]byte
	var ks6 [][21]byte
	i4 := m4.Iterate()
	for i4.Next(&k4, &v) {
		ks4 = append(ks4, k4)
	}
	for _, k := range ks4 {
		_ = m4.Delete(k)
	}
	if err := mapIterErr(i4.Err()); err != nil {
		return err
	}
	i6 := m6.Iterate()
	for i6.Next(&k6, &v) {
		ks6 = append(ks6, k6)
	}
	for _, k := range ks6 {
		_ = m6.Delete(k)
	}
	if err := mapIterErr(i6.Err()); err != nil {
		return err
	}
	for _, r := range rules {
		ip, n, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			continue
		}
		ones, _ := n.Mask.Size()
		for _, d := range dirs(r.Direction) {
			if v4 := ip.To4(); v4 != nil {
				var k [9]byte
				native.PutUint32(k[0:4], uint32(8+ones))
				k[4] = d
				copy(k[5:9], v4)
				if err := m4.Put(k, uint8(1)); err != nil {
					return err
				}
			} else {
				var k [21]byte
				native.PutUint32(k[0:4], uint32(8+ones))
				k[4] = d
				copy(k[5:21], ip.To16())
				if err := m6.Put(k, uint8(1)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (a *Agent) replaceAllowedCIDRs(rules []models.EBPFCIDRRule) error {
	m4, m6 := a.collection.Maps["allowed_cidr_v4"], a.collection.Maps["allowed_cidr_v6"]
	if m4 == nil || m6 == nil {
		return nil
	}
	return a.replaceCIDRMaps(m4, m6, rules)
}

func protoNum(s string) byte {
	switch strings.ToUpper(s) {
	case "TCP":
		return 6
	case "UDP":
		return 17
	default:
		return 0
	}
}
func (a *Agent) replacePorts(rules []models.EBPFPortRule) error {
	return a.replacePortMap("blocked_ports", rules)
}

func (a *Agent) replacePortMap(name string, rules []models.EBPFPortRule) error {
	m := a.collection.Maps[name]
	if m == nil {
		if name != "blocked_ports" {
			return nil
		}
		return fmt.Errorf("map %s unavailable", name)
	}
	var k [4]byte
	var v uint8
	var keys [][4]byte
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = m.Delete(x)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return err
	}
	for _, r := range rules {
		for _, d := range dirs(r.Direction) {
			var k [4]byte
			k[0] = d
			k[1] = protoNum(r.Protocol)
			binary.BigEndian.PutUint16(k[2:4], r.Port)
			if err := m.Put(k, uint8(1)); err != nil {
				return err
			}
		}
	}
	return nil
}
func (a *Agent) replaceUIDs(values []uint32) error {
	return a.replaceUIDMap("blocked_uids", values)
}

func (a *Agent) replaceUIDMap(name string, values []uint32) error {
	m := a.collection.Maps[name]
	if m == nil {
		if name != "blocked_uids" {
			return nil
		}
		return fmt.Errorf("map %s unavailable", name)
	}
	var k uint32
	var v uint8
	var keys []uint32
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = m.Delete(x)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return err
	}
	for _, x := range values {
		if err := m.Put(x, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}
func (a *Agent) replaceStringMap(name string, values []string, size int) error {
	m := a.collection.Maps[name]
	if m == nil {
		return fmt.Errorf("map %s unavailable", name)
	}
	if size == 96 {
		var k [96]byte
		var v uint8
		var keys [][96]byte
		it := m.Iterate()
		for it.Next(&k, &v) {
			keys = append(keys, k)
		}
		for _, x := range keys {
			_ = m.Delete(x)
		}
		if err := mapIterErr(it.Err()); err != nil {
			return err
		}
		for _, s := range values {
			var q [96]byte
			copy(q[:], []byte(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))))
			if err := m.Put(q, uint8(1)); err != nil {
				return err
			}
		}
		return nil
	}
	var k [16]byte
	var v uint8
	var keys [][16]byte
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = m.Delete(x)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return err
	}
	for _, s := range values {
		var q [16]byte
		copy(q[:], []byte(strings.TrimSpace(s)))
		if err := m.Put(q, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) replaceRates(values []models.EBPFRateLimit) error {
	m4 := a.collection.Maps["rate_v4"]
	if m4 == nil {
		return fmt.Errorf("map rate_v4 unavailable")
	}
	var k [4]byte
	var v uint32
	var keys [][4]byte
	it := m4.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = m4.Delete(x)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return err
	}
	m6 := a.collection.Maps["rate_v6"]
	if m6 != nil {
		var k6 [16]byte
		var v6 uint32
		var keys6 [][16]byte
		it6 := m6.Iterate()
		for it6.Next(&k6, &v6) {
			keys6 = append(keys6, k6)
		}
		for _, x := range keys6 {
			_ = m6.Delete(x)
		}
		if err := mapIterErr(it6.Err()); err != nil {
			return err
		}
	}
	for _, r := range values {
		if r.PPS == 0 {
			continue
		}
		ip := net.ParseIP(r.Destination)
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			var q [4]byte
			copy(q[:], v4)
			if err := m4.Put(q, r.PPS); err != nil {
				return err
			}
			continue
		}
		if m6 == nil {
			continue
		}
		var q6 [16]byte
		copy(q6[:], ip.To16())
		if err := m6.Put(q6, r.PPS); err != nil {
			return err
		}
	}
	return nil
}

// replaceByteRates is replaceRates' BPS counterpart — same full
// clear-then-rewrite convention, writing to the parallel rate_bps_v4/v6
// maps instead. A destination can have a PPS entry, a BPS entry, both, or
// neither; the two maps are independent.
func (a *Agent) replaceByteRates(values []models.EBPFRateLimit) error {
	m4 := a.collection.Maps["rate_bps_v4"]
	if m4 == nil {
		return fmt.Errorf("map rate_bps_v4 unavailable")
	}
	var k [4]byte
	var v uint32
	var keys [][4]byte
	it := m4.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = m4.Delete(x)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return err
	}
	m6 := a.collection.Maps["rate_bps_v6"]
	if m6 != nil {
		var k6 [16]byte
		var v6 uint32
		var keys6 [][16]byte
		it6 := m6.Iterate()
		for it6.Next(&k6, &v6) {
			keys6 = append(keys6, k6)
		}
		for _, x := range keys6 {
			_ = m6.Delete(x)
		}
		if err := mapIterErr(it6.Err()); err != nil {
			return err
		}
	}
	for _, r := range values {
		if r.BPS == 0 {
			continue
		}
		ip := net.ParseIP(r.Destination)
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			var q [4]byte
			copy(q[:], v4)
			if err := m4.Put(q, r.BPS); err != nil {
				return err
			}
			continue
		}
		if m6 == nil {
			continue
		}
		var q6 [16]byte
		copy(q6[:], ip.To16())
		if err := m6.Put(q6, r.BPS); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) applyWorkloadScopes(cfg models.EBPFFastPathConfig) error {
	mode := strings.ToLower(strings.TrimSpace(cfg.ScopeMode))
	if mode == "" {
		mode = "all"
	}
	scopeMap := a.collection.Maps["scope_config"]
	enforced := a.collection.Maps["enforced_cgroups"]
	if scopeMap == nil || enforced == nil {
		return fmt.Errorf("workload scope maps unavailable")
	}
	selectedMode := uint32(0)
	if mode == "selected" {
		selectedMode = 1
	}
	if err := scopeMap.Put(uint32(0), selectedMode); err != nil {
		return err
	}

	var key uint64
	var value uint8
	var old []uint64
	it := enforced.Iterate()
	for it.Next(&key, &value) {
		old = append(old, key)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return err
	}
	for _, k := range old {
		_ = enforced.Delete(k)
	}

	cgroups, err := a.scanCgroups()
	if err != nil {
		return fmt.Errorf("scan cgroup metadata: %w", err)
	}
	resolved, selected := workload.Resolve(cgroups, cfg.Workloads, cfg.WorkloadScopes)
	if mode == "selected" {
		for id := range selected {
			if err := enforced.Put(id, uint8(1)); err != nil {
				return err
			}
		}
	}
	a.scopeMode, a.selectedCgroups = mode, len(selected)
	a.workloadMu.Lock()
	a.workloadByCgroup = resolved
	a.workloadMu.Unlock()
	return nil
}

// applyConnRateLimits resolves every EBPFConnRateLimit.Selector against the
// node's live cgroup→workload table (populated by applyWorkloadScopes,
// called just before this every sync) and pushes the resulting per-cgroup
// PPS ceiling into conn_rate_limits — a full clear-then-rewrite each sync,
// same convention as replaceRates. When more than one rule matches a
// cgroup, the strictest (lowest) PerSecond wins, consistent with "these are
// caps, not quotas that sum."
func (a *Agent) applyConnRateLimits(cfg models.EBPFFastPathConfig) error {
	m := a.collection.Maps["conn_rate_limits"]
	if m == nil {
		return fmt.Errorf("conn_rate_limits unavailable")
	}
	var oldKey uint64
	var oldVal uint32
	var stale []uint64
	it := m.Iterate()
	for it.Next(&oldKey, &oldVal) {
		stale = append(stale, oldKey)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return err
	}
	for _, k := range stale {
		_ = m.Delete(k)
	}
	if len(cfg.ConnRateLimits) == 0 {
		return nil
	}
	a.workloadMu.RLock()
	byCgroup := a.workloadByCgroup
	a.workloadMu.RUnlock()
	effective := effectiveConnRateLimits(byCgroup, cfg.ConnRateLimits)
	for cgroupID, pps := range effective {
		if err := m.Put(cgroupID, pps); err != nil {
			return err
		}
	}
	return nil
}

// effectiveConnRateLimits matches every rule's Selector against every
// cgroup's resolved workload identity, keeping the strictest (lowest)
// PerSecond when more than one rule matches a cgroup. Pulled out of
// applyConnRateLimits so the matching/min-selection logic is unit-testable
// without a live BPF map.
func effectiveConnRateLimits(byCgroup map[uint64]models.WorkloadIdentity, rules []models.EBPFConnRateLimit) map[uint64]uint32 {
	effective := make(map[uint64]uint32, len(byCgroup))
	for cgroupID, w := range byCgroup {
		for _, rule := range rules {
			if rule.PerSecond == 0 || !workload.Match(rule.Selector, w) {
				continue
			}
			if cur, ok := effective[cgroupID]; !ok || rule.PerSecond < cur {
				effective[cgroupID] = rule.PerSecond
			}
		}
	}
	return effective
}

func (a *Agent) scanCgroups() (map[uint64]cgroupmeta.Identity, error) {
	if a.cgroupCache != nil && a.cgroupScanEvery > 0 && time.Since(a.lastCgroupScan) < a.cgroupScanEvery {
		return a.cgroupCache, nil
	}
	items, err := cgroupmeta.Scan(a.cgroupPath)
	if err != nil {
		return nil, err
	}
	a.cgroupCache, a.lastCgroupScan = items, time.Now()
	return items, nil
}

func (a *Agent) workloadSnapshot() []models.WorkloadIdentity {
	a.workloadMu.RLock()
	defer a.workloadMu.RUnlock()
	return workload.Sorted(a.workloadByCgroup)
}
func (a *Agent) workloadIdentity(id uint64) (models.WorkloadIdentity, bool) {
	a.workloadMu.RLock()
	defer a.workloadMu.RUnlock()
	w, ok := a.workloadByCgroup[id]
	return w, ok
}
func (a *Agent) enrichEvent(e *models.FastPathEvent) {
	if e.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(e.CgroupID); ok {
		e.Namespace, e.Pod, e.WorkloadKind, e.WorkloadName, e.ContainerID = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName, w.ContainerID
	}
}
func (a *Agent) enrichStat(st *models.DestinationStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName, st.ContainerID = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName, w.ContainerID
	}
}

func (a *Agent) enrichTCPHealth(st *models.TCPHealthStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName, st.ContainerID = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName, w.ContainerID
	}
}
func (a *Agent) enrichUDPFlowHealth(st *models.UDPFlowHealthStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}
func (a *Agent) enrichTCPPressure(st *models.TCPPressureStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}
func (a *Agent) enrichConnectLatency(st *models.ConnectLatencyStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}

func (a *Agent) enrichTCPSignal(st *models.TCPSignalStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}
func (a *Agent) enrichDNSHealth(st *models.DNSHealthStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}
func (a *Agent) enrichTLSMetadata(st *models.TLSMetadataStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}
func (a *Agent) enrichHTTPMetadata(st *models.HTTPMetadataStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}
func (a *Agent) enrichHTTPStatus(st *models.HTTPStatusStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}
func (a *Agent) enrichConnectionAttempt(st *models.ConnectionAttemptStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}

func decodeUDPFlowHealth(k [56]byte, v [24]byte) models.UDPFlowHealthStat {
	family := k[8]
	localIP, remoteIP := "", ""
	if family == 4 {
		localIP = net.IP(k[12:16]).String()
		remoteIP = net.IP(k[16:20]).String()
	}
	if family == 6 {
		localIP = net.IP(k[20:36]).String()
		remoteIP = net.IP(k[36:52]).String()
	}
	return models.UDPFlowHealthStat{
		CgroupID: native.Uint64(k[0:8]), Family: familyName(family), LocalIP: localIP, RemoteIP: remoteIP,
		LocalPort: native.Uint16(k[52:54]), RemotePort: native.Uint16(k[54:56]),
		Packets: native.Uint64(v[0:8]), Bytes: native.Uint64(v[8:16]), LastSeenNS: native.Uint64(v[16:24]),
	}
}

// Key layout: cgroup_id[0:8], family[8], pad[9:12], remote_addr[12:28],
// remote_port[28:30], pad2[30:32] — see quic_observed_key in bpf/netra_tc.c
// and its _Static_assert-guarded mirror in bpf/tests/abi_layout_test.c.
func decodeQUICObserved(k [32]byte, v [24]byte) models.QUICObservedStat {
	family := k[8]
	remoteIP := ""
	if family == 4 {
		remoteIP = net.IP(k[12:16]).String()
	}
	if family == 6 {
		remoteIP = net.IP(k[12:28]).String()
	}
	return models.QUICObservedStat{
		CgroupID: native.Uint64(k[0:8]), Family: familyName(family), RemoteIP: remoteIP,
		RemotePort: native.Uint16(k[28:30]),
		Packets:    native.Uint64(v[0:8]), LongHeaderPackets: native.Uint64(v[8:16]), LastSeenNS: native.Uint64(v[16:24]),
	}
}

func (a *Agent) enrichQUICObserved(st *models.QUICObservedStat) {
	if st.CgroupID == 0 {
		return
	}
	if w, ok := a.workloadIdentity(st.CgroupID); ok {
		st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
	}
}

func (a *Agent) readTCPPressure() ([]models.TCPPressureStat, error) {
	m := a.collection.Maps["tcp_pressure"]
	if m == nil {
		return nil, fmt.Errorf("tcp_pressure unavailable")
	}
	it := m.Iterate()
	var k [56]byte
	var v [104]byte
	out := make([]models.TCPPressureStat, 0, 256)
	for it.Next(&k, &v) {
		family := k[8]
		localIP, remoteIP := "", ""
		if family == 4 {
			localIP = net.IP(k[12:16]).String()
			remoteIP = net.IP(k[16:20]).String()
		}
		if family == 6 {
			localIP = net.IP(k[20:36]).String()
			remoteIP = net.IP(k[36:52]).String()
		}
		st := models.TCPPressureStat{
			CgroupID: native.Uint64(k[0:8]), Family: familyName(family), LocalIP: localIP, RemoteIP: remoteIP, LocalPort: native.Uint16(k[52:54]), RemotePort: native.Uint16(k[54:56]),
			Callbacks: native.Uint64(v[0:8]), SendCWND: native.Uint64(v[8:16]), SendSSThresh: native.Uint64(v[16:24]), PacketsOut: native.Uint64(v[24:32]),
			RetransOut: native.Uint64(v[32:40]), TotalRetrans: native.Uint64(v[40:48]), LostOut: native.Uint64(v[48:56]), SackedOut: native.Uint64(v[56:64]),
			RateDelivered: native.Uint64(v[64:72]), RateIntervalUS: native.Uint64(v[72:80]), MSS: native.Uint64(v[80:88]), TCPState: native.Uint64(v[88:96]), LastSeenNS: native.Uint64(v[96:104]),
		}
		a.enrichTCPPressure(&st)
		out = append(out, st)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LostOut*100000+out[i].RetransOut*10000+out[i].PacketsOut > out[j].LostOut*100000+out[j].RetransOut*10000+out[j].PacketsOut
	})
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

func (a *Agent) readConnectLatency() ([]models.ConnectLatencyStat, error) {
	m := a.collection.Maps["connect_health"]
	if m == nil {
		return nil, fmt.Errorf("connect_health unavailable")
	}
	it := m.Iterate()
	var k [28]byte
	var v [32]byte
	out := make([]models.ConnectLatencyStat, 0, 256)
	for it.Next(&k, &v) {
		family := k[8]
		remote := ""
		if family == 4 {
			remote = net.IP(k[12:16]).String()
		} else if family == 6 {
			remote = net.IP(k[12:28]).String()
		}
		st := models.ConnectLatencyStat{CgroupID: native.Uint64(k[0:8]), Family: familyName(family), RemotePort: binary.BigEndian.Uint16(k[10:12]), RemoteIP: remote, Established: native.Uint64(v[0:8]), TotalLatencyUS: native.Uint64(v[8:16]), MaxLatencyUS: native.Uint64(v[16:24]), LastSeenNS: native.Uint64(v[24:32])}
		a.enrichConnectLatency(&st)
		out = append(out, st)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		ai, aj := uint64(0), uint64(0)
		if out[i].Established > 0 {
			ai = out[i].TotalLatencyUS / out[i].Established
		}
		if out[j].Established > 0 {
			aj = out[j].TotalLatencyUS / out[j].Established
		}
		return ai > aj
	})
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

func (a *Agent) readTCPSignals() ([]models.TCPSignalStat, error) {
	m := a.collection.Maps["tcp_signals"]
	if m == nil {
		return nil, fmt.Errorf("tcp_signals unavailable")
	}
	it := m.Iterate()
	var k uint64
	var v [40]byte
	out := make([]models.TCPSignalStat, 0, 128)
	for it.Next(&k, &v) {
		st := models.TCPSignalStat{CgroupID: k, SYN: native.Uint64(v[0:8]), SYNACK: native.Uint64(v[8:16]), FIN: native.Uint64(v[16:24]), RST: native.Uint64(v[24:32]), Packets: native.Uint64(v[32:40])}
		a.enrichTCPSignal(&st)
		out = append(out, st)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RST > out[j].RST })
	return out, nil
}

func (a *Agent) readDNSHealth() ([]models.DNSHealthStat, error) {
	m := a.collection.Maps["dns_health"]
	if m == nil {
		return nil, fmt.Errorf("dns_health unavailable")
	}
	it := m.Iterate()
	var k [104]byte
	var v [48]byte
	out := make([]models.DNSHealthStat, 0, 128)
	for it.Next(&k, &v) {
		st := models.DNSHealthStat{CgroupID: native.Uint64(k[0:8]), Name: cString(k[8:104]), Queries: native.Uint64(v[0:8]), Responses: native.Uint64(v[8:16]), Failures: native.Uint64(v[16:24]), TotalLatencyUS: native.Uint64(v[24:32]), MaxLatencyUS: native.Uint64(v[32:40]), LastSeenNS: native.Uint64(v[40:48])}
		a.enrichDNSHealth(&st)
		out = append(out, st)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		fi, fj := out[i].Failures, out[j].Failures
		if fi != fj {
			return fi > fj
		}
		return out[i].MaxLatencyUS > out[j].MaxLatencyUS
	})
	if len(out) > models.ReportCapDNS {
		out = out[:models.ReportCapDNS]
	}
	return out, nil
}

func (a *Agent) readTLSMetadata() ([]models.TLSMetadataStat, error) {
	m := a.collection.Maps["tls_sni_stats"]
	if m == nil {
		return nil, fmt.Errorf("tls_sni_stats unavailable")
	}
	it := m.Iterate()
	var k [104]byte
	var v [24]byte
	out := make([]models.TLSMetadataStat, 0, 128)
	for it.Next(&k, &v) {
		st := models.TLSMetadataStat{CgroupID: native.Uint64(k[0:8]), SNI: cString(k[8:104]), Handshakes: native.Uint64(v[0:8]), Blocked: native.Uint64(v[8:16]), LastSeenNS: native.Uint64(v[16:24])}
		a.enrichTLSMetadata(&st)
		out = append(out, st)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Handshakes > out[j].Handshakes })
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

func (a *Agent) readHTTPMetadata() ([]models.HTTPMetadataStat, error) {
	m := a.collection.Maps["http_host_stats"]
	if m == nil {
		return nil, fmt.Errorf("http_host_stats unavailable")
	}
	it := m.Iterate()
	var k [112]byte
	var v [16]byte
	out := make([]models.HTTPMetadataStat, 0, 128)
	for it.Next(&k, &v) {
		st := models.HTTPMetadataStat{CgroupID: native.Uint64(k[0:8]), Host: cString(k[8:104]), Method: cString(k[104:112]), Requests: native.Uint64(v[0:8]), LastSeenNS: native.Uint64(v[8:16])}
		a.enrichHTTPMetadata(&st)
		out = append(out, st)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requests > out[j].Requests })
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

func (a *Agent) readHTTPStatus() ([]models.HTTPStatusStat, error) {
	m := a.collection.Maps["http_status_stats"]
	if m == nil {
		return nil, nil
	}
	it := m.Iterate()
	var k [16]byte
	var v [16]byte
	out := make([]models.HTTPStatusStat, 0, 64)
	for it.Next(&k, &v) {
		st := models.HTTPStatusStat{
			CgroupID:   native.Uint64(k[0:8]),
			Status:     native.Uint16(k[8:10]),
			Count:      native.Uint64(v[0:8]),
			LastSeenNS: native.Uint64(v[8:16]),
		}
		if st.Status < 100 || st.Status > 599 || st.Count == 0 {
			continue
		}
		a.enrichHTTPStatus(&st)
		out = append(out, st)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Status < out[j].Status
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > models.ReportCapHTTPStatus {
		out = out[:models.ReportCapHTTPStatus]
	}
	return out, nil
}

func (a *Agent) readConnectionAttempts() ([]models.ConnectionAttemptStat, error) {
	m := a.collection.Maps["connect_attempts"]
	if m == nil {
		return nil, fmt.Errorf("connect_attempts unavailable")
	}
	it := m.Iterate()
	var k [28]byte
	var v [24]byte
	out := make([]models.ConnectionAttemptStat, 0, 256)
	for it.Next(&k, &v) {
		family := k[8]
		remote := ""
		if family == 4 {
			remote = net.IP(k[12:16]).String()
		} else if family == 6 {
			remote = net.IP(k[12:28]).String()
		}
		st := models.ConnectionAttemptStat{CgroupID: native.Uint64(k[0:8]), Family: familyName(family), Protocol: protoName(k[9]), RemotePort: binary.BigEndian.Uint16(k[10:12]), RemoteIP: remote, Attempts: native.Uint64(v[0:8]), Blocked: native.Uint64(v[8:16]), LastSeenNS: native.Uint64(v[16:24])}
		a.enrichConnectionAttempt(&st)
		out = append(out, st)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Attempts > out[j].Attempts })
	if len(out) > models.ReportCapConnAttempts {
		out = out[:models.ReportCapConnAttempts]
	}
	return out, nil
}

func (a *Agent) readEvents(ctx context.Context) {
	m := a.collection.Maps["events"]
	if m == nil {
		return
	}
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		a.log.Warn("open eBPF ring buffer", "error", err)
		return
	}
	defer rd.Close()
	go func() { <-ctx.Done(); _ = rd.Close() }()
	for {
		record, err := rd.Read()
		if err != nil {
			if ctx.Err() == nil {
				a.log.Warn("read eBPF ring buffer", "error", err)
			}
			return
		}
		b := record.RawSample
		if len(b) < 196 {
			continue
		}
		family := b[68]
		src, dst := "", ""
		if family == 4 {
			src = net.IP(b[32:36]).String()
			dst = net.IP(b[48:52]).String()
		} else if family == 6 {
			src = net.IP(b[32:48]).String()
			dst = net.IP(b[48:64]).String()
		}
		e := models.FastPathEvent{TimestampNS: native.Uint64(b[0:8]), CgroupID: native.Uint64(b[8:16]), PID: native.Uint32(b[16:20]), UID: native.Uint32(b[20:24]), InterfaceIndex: native.Uint32(b[24:28]), Length: native.Uint32(b[28:32]), SourceIP: src, DestinationIP: dst, SourcePort: binary.BigEndian.Uint16(b[64:66]), DestinationPort: binary.BigEndian.Uint16(b[66:68]), Family: familyName(family), Protocol: protoName(b[69]), Direction: dirName(b[70]), Hook: hookName(b[71]), Action: actionName(b[72]), Type: eventName(b[73]), TCPFlags: b[74], Reason: reasonName(b[75]), Comm: cString(b[76:92]), DNSQuery: cString(b[92:188]), LatencyUS: native.Uint32(b[188:192]), DNSRcode: b[192], ObservedAt: time.Now().UTC()}
		a.enrichEvent(&e)
		select {
		case a.events <- e:
		default:
		}
	}
}
func (a *Agent) drainEvents(limit int) []models.FastPathEvent {
	out := make([]models.FastPathEvent, 0, limit)
	for len(out) < limit {
		select {
		case e := <-a.events:
			out = append(out, e)
		default:
			return out
		}
	}
	return out
}

// tls_hello_event layout (packed): cgroup_id(8) ts_ns(8) copy_len(2) pad(2) data[256]
const tlsHelloEventSize = 8 + 8 + 2 + 2 + 256

func (a *Agent) readTLSHelloEvents(ctx context.Context) {
	var m *ebpf.Map
	if a.tlsfpCollection != nil {
		m = a.tlsfpCollection.Maps["tls_hello_events"]
	}
	if m == nil && a.collection != nil {
		m = a.collection.Maps["tls_hello_events"]
	}
	if m == nil || a.tlsFP == nil {
		return
	}
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		a.log.Warn("open tls_hello_events ring buffer", "error", err)
		return
	}
	defer rd.Close()
	go func() { <-ctx.Done(); _ = rd.Close() }()
	for {
		record, err := rd.Read()
		if err != nil {
			if ctx.Err() == nil {
				a.log.Warn("read tls_hello_events", "error", err)
			}
			return
		}
		b := record.RawSample
		if len(b) < tlsHelloEventSize {
			continue
		}
		cgroupID := native.Uint64(b[0:8])
		copyLen := int(native.Uint16(b[16:18]))
		if copyLen <= 0 || copyLen > 256 {
			continue
		}
		hello := b[20 : 20+copyLen]
		fp, err := tlsfp.ParseClientHello(hello)
		if err != nil || fp == nil || fp.JA3 == "" {
			continue
		}
		a.tlsFP.Observe("", *fp)
		// Stash cgroup on a side channel via Observe is node-only; enrich at drain.
		a.noteTLSHelloCgroup(fp.JA3, cgroupID)
	}
}

func (a *Agent) noteTLSHelloCgroup(ja3 string, cgroupID uint64) {
	if ja3 == "" || cgroupID == 0 {
		return
	}
	a.workloadMu.Lock()
	defer a.workloadMu.Unlock()
	if a.tlsFPCgroups == nil {
		a.tlsFPCgroups = map[string]uint64{}
	}
	a.tlsFPCgroups[ja3] = cgroupID
}

func (a *Agent) drainTLSFingerprints(limit int) []models.TLSFingerprintStat {
	if a.tlsFP == nil {
		return nil
	}
	snap := a.tlsFP.Snapshot(limit)
	if len(snap) == 0 {
		return nil
	}
	a.workloadMu.RLock()
	cgByJA3 := a.tlsFPCgroups
	a.workloadMu.RUnlock()
	out := make([]models.TLSFingerprintStat, 0, len(snap))
	for _, o := range snap {
		st := models.TLSFingerprintStat{
			JA3: o.JA3, JA4: o.JA4, SNI: o.SNI, ECH: o.ECH, Count: o.Count, Source: "datapath",
		}
		if cgByJA3 != nil {
			if cg := cgByJA3[o.JA3]; cg != 0 {
				st.CgroupID = cg
				if w, ok := a.workloadIdentity(cg); ok {
					st.Namespace, st.Pod = w.Namespace, w.Pod
					st.WorkloadKind, st.WorkloadName = w.WorkloadKind, w.WorkloadName
				}
			}
		}
		out = append(out, st)
	}
	return out
}

func (a *Agent) readKernelDrops() ([]models.KernelDropStat, error) {
	m := a.collection.Maps["kernel_drops"]
	if m == nil {
		return nil, nil
	}
	type key struct {
		Reason uint32
		Pad    uint32
	}
	type value struct {
		Count  uint64
		LastNS uint64
	}
	var k key
	var v value
	out := make([]models.KernelDropStat, 0, 128)
	it := m.Iterate()
	for it.Next(&k, &v) {
		out = append(out, models.KernelDropStat{Reason: k.Reason, ReasonName: dropreason.Name(k.Reason), Count: v.Count, LastSeenNS: v.LastNS})
		if len(out) >= 4096 {
			break
		}
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out, nil
}

func icmpTypeName(v4 bool, typ uint8) string {
	if v4 {
		switch typ {
		case 0:
			return "echo-reply"
		case 3:
			return "dest-unreach"
		case 8:
			return "echo-request"
		case 11:
			return "time-exceeded"
		}
		return fmt.Sprintf("icmp-%d", typ)
	}
	switch typ {
	case 1:
		return "dest-unreach"
	case 2:
		return "pkt-too-big"
	case 3:
		return "time-exceeded"
	case 128:
		return "echo-request"
	case 129:
		return "echo-reply"
	}
	return fmt.Sprintf("icmp6-%d", typ)
}

func (a *Agent) readICMPTypeStats(mapName string) ([]models.NamedCount, error) {
	m := a.collection.Maps[mapName]
	if m == nil {
		return nil, nil
	}
	var k uint8
	var v uint64
	out := make([]models.NamedCount, 0, 16)
	it := m.Iterate()
	v4 := mapName == "icmp_type_stats"
	for it.Next(&k, &v) {
		out = append(out, models.NamedCount{Name: icmpTypeName(v4, k), Count: v})
		if len(out) >= 32 {
			break
		}
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out, nil
}

// missingMaps also folds in a.captureBackendErr when set — a capture
// backend explicitly requested by an operator (either "ebpf" or
// "afpacket") that this node couldn't actually provide is the same
// "requested capability unavailable on this node" category this field
// already reports for missing fast-path maps, so it's surfaced the same
// way rather than inventing a second node-health channel.
func (a *Agent) missingMaps() []string {
	var out []string
	if a.collection == nil {
		out = append(out, mapNames...)
	} else {
		for _, n := range mapNames {
			if a.collection.Maps[n] == nil {
				out = append(out, n)
			}
		}
	}
	if a.captureBackendErr != "" {
		out = append(out, a.captureBackendErr)
	}
	return out
}

func (a *Agent) readRateDrops() ([]models.NamedCount, error) {
	out := make([]models.NamedCount, 0, 16)
	if m := a.collection.Maps["rate_state_v4"]; m != nil {
		var k [4]byte
		var v struct {
			Second  uint64
			Count   uint64
			Dropped uint64
		}
		it := m.Iterate()
		for it.Next(&k, &v) {
			if v.Dropped == 0 {
				continue
			}
			out = append(out, models.NamedCount{Name: net.IP(k[:]).String(), Count: v.Dropped})
			if len(out) >= 32 {
				break
			}
		}
		if err := mapIterErr(it.Err()); err != nil {
			return nil, err
		}
	}
	if m := a.collection.Maps["rate_state_v6"]; m != nil && len(out) < 32 {
		var k [16]byte
		var v struct {
			Second  uint64
			Count   uint64
			Dropped uint64
		}
		it := m.Iterate()
		for it.Next(&k, &v) {
			if v.Dropped == 0 {
				continue
			}
			out = append(out, models.NamedCount{Name: net.IP(k[:]).String(), Count: v.Dropped})
			if len(out) >= 32 {
				break
			}
		}
		if err := mapIterErr(it.Err()); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out, nil
}

// readByteRateDrops is readRateDrops' BPS counterpart, reading
// rate_byte_state_v4/v6 (the parallel maps replaceByteRates populates)
// instead — a separate signal from RateDrops since a destination's PPS and
// BPS caps fire independently.
func (a *Agent) readByteRateDrops() ([]models.NamedCount, error) {
	out := make([]models.NamedCount, 0, 16)
	if m := a.collection.Maps["rate_byte_state_v4"]; m != nil {
		var k [4]byte
		var v struct {
			Second  uint64
			Count   uint64
			Dropped uint64
		}
		it := m.Iterate()
		for it.Next(&k, &v) {
			if v.Dropped == 0 {
				continue
			}
			out = append(out, models.NamedCount{Name: net.IP(k[:]).String(), Count: v.Dropped})
			if len(out) >= 32 {
				break
			}
		}
		if err := mapIterErr(it.Err()); err != nil {
			return nil, err
		}
	}
	if m := a.collection.Maps["rate_byte_state_v6"]; m != nil && len(out) < 32 {
		var k [16]byte
		var v struct {
			Second  uint64
			Count   uint64
			Dropped uint64
		}
		it := m.Iterate()
		for it.Next(&k, &v) {
			if v.Dropped == 0 {
				continue
			}
			out = append(out, models.NamedCount{Name: net.IP(k[:]).String(), Count: v.Dropped})
			if len(out) >= 32 {
				break
			}
		}
		if err := mapIterErr(it.Err()); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out, nil
}

// readConnRateDrops names entries by workload identity when resolvable
// (mirroring every other cgroup-keyed reader's enrichment), falling back to
// "cgroup N" — unlike readRateDrops, an IP string isn't meaningful here
// since conn_rate_state is keyed by cgroup_id, not destination address.
func (a *Agent) readConnRateDrops() ([]models.NamedCount, error) {
	m := a.collection.Maps["conn_rate_state"]
	if m == nil {
		return nil, fmt.Errorf("conn_rate_state unavailable")
	}
	out := make([]models.NamedCount, 0, 16)
	var k uint64
	var v struct {
		Second  uint64
		Count   uint64
		Dropped uint64
	}
	it := m.Iterate()
	for it.Next(&k, &v) {
		if v.Dropped == 0 {
			continue
		}
		name := fmt.Sprintf("cgroup %d", k)
		if w, ok := a.workloadIdentity(k); ok && w.Namespace != "" {
			name = w.Namespace + "/" + w.Pod
		}
		out = append(out, models.NamedCount{Name: name, Count: v.Dropped})
		if len(out) >= 32 {
			break
		}
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out, nil
}

func (a *Agent) readIPv6ExtStats() ([]models.IPv6ExtHeaderStat, error) {
	m := a.collection.Maps["ipv6_ext_stats"]
	if m == nil {
		return nil, nil
	}
	type key struct {
		Direction uint8
		Hook      uint8
		Pad       uint16
	}
	type value struct {
		Packets           uint64
		ExtHeaderPackets  uint64
		TotalExtHeaders   uint64
		Fragmented        uint64
		NonFirstFragments uint64
		MoreFragments     uint64
		ChainTruncated    uint64
	}
	var k key
	var v value
	out := make([]models.IPv6ExtHeaderStat, 0, 16)
	it := m.Iterate()
	for it.Next(&k, &v) {
		out = append(out, models.IPv6ExtHeaderStat{
			Direction:         dirName(k.Direction),
			Hook:              hookName(k.Hook),
			Packets:           v.Packets,
			ExtHeaderPackets:  v.ExtHeaderPackets,
			TotalExtHeaders:   v.TotalExtHeaders,
			Fragmented:        v.Fragmented,
			NonFirstFragments: v.NonFirstFragments,
			MoreFragments:     v.MoreFragments,
			ChainTruncated:    v.ChainTruncated,
		})
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Packets > out[j].Packets })
	return out, nil
}

func (a *Agent) readPolicyDrops() ([]models.PolicyDropStat, error) {
	m := a.collection.Maps["policy_drops"]
	if m == nil {
		return nil, nil
	}
	type key struct {
		Family    uint8
		Protocol  uint8
		Direction uint8
		Reason    uint8
		SrcPort   uint16
		DstPort   uint16
		SrcAddr   [16]byte
		DstAddr   [16]byte
	}
	type value struct {
		Packets uint64
		Bytes   uint64
		LastNS  uint64
	}
	var k key
	var v value
	out := make([]models.PolicyDropStat, 0, 128)
	it := m.Iterate()
	for it.Next(&k, &v) {
		src, dst := "", ""
		if k.Family == 4 {
			src = net.IP(k.SrcAddr[:4]).String()
			dst = net.IP(k.DstAddr[:4]).String()
		} else {
			src = net.IP(k.SrcAddr[:]).String()
			dst = net.IP(k.DstAddr[:]).String()
		}
		out = append(out, models.PolicyDropStat{
			Family: k.Family, Protocol: k.Protocol, Direction: k.Direction, Reason: k.Reason,
			SrcAddr: src, DstAddr: dst, SrcPort: k.SrcPort, DstPort: k.DstPort,
			Packets: v.Packets, Bytes: v.Bytes, LastNS: v.LastNS,
		})
		if len(out) >= 4096 {
			break
		}
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Packets > out[j].Packets })
	return out, nil
}

func (a *Agent) readShieldStats() (*models.ShieldStats, error) {
	m := a.collection.Maps["shield_stats"]
	if m == nil {
		return nil, nil
	}
	var zero uint32
	var v struct {
		Allowed uint64
		Dropped uint64
		Audited uint64
	}
	if err := m.Lookup(&zero, &v); err != nil {
		return nil, nil
	}
	return &models.ShieldStats{Allowed: v.Allowed, Dropped: v.Dropped, Audited: v.Audited}, nil
}

func shieldClassName(id uint32) string {
	switch id {
	case 1:
		return "syn"
	case 2:
		return "udp"
	case 3:
		return "icmp"
	case 4:
		return "other"
	default:
		return "unknown"
	}
}

// readShieldClassStats reads the fixed 5-entry shield_class_stats array
// (index 0 unused, 1-4 = syn/udp/icmp/other), a new map added alongside
// the existing, unresized shield_stats array.
func (a *Agent) readShieldClassStats() ([]models.ShieldClassStat, error) {
	m := a.collection.Maps["shield_class_stats"]
	if m == nil {
		return nil, nil
	}
	type value struct {
		Allowed uint64
		Dropped uint64
		Audited uint64
	}
	out := make([]models.ShieldClassStat, 0, 4)
	for id := uint32(1); id <= 4; id++ {
		var v value
		if err := m.Lookup(&id, &v); err != nil {
			continue
		}
		if v.Allowed == 0 && v.Dropped == 0 && v.Audited == 0 {
			continue
		}
		out = append(out, models.ShieldClassStat{Class: shieldClassName(id), Allowed: v.Allowed, Dropped: v.Dropped, Audited: v.Audited})
	}
	return out, nil
}

// readShieldSourceHits reads the new shield_source_hits LRU map, bounding
// and pre-sorting agent-side so the controller only needs to merge and
// re-truncate a small top-N across nodes, not build one from scratch.
func (a *Agent) readShieldSourceHits() ([]models.ShieldSourceStat, error) {
	m := a.collection.Maps["shield_source_hits"]
	if m == nil {
		return nil, nil
	}
	type key struct {
		Family  uint8
		ClassID uint8
		Pad     uint16
		Addr    [16]byte
	}
	type value struct {
		Denied   uint64
		LastNS   uint64
		Attempts uint64
	}
	var k key
	var v value
	out := make([]models.ShieldSourceStat, 0, 200)
	it := m.Iterate()
	for it.Next(&k, &v) {
		addr := ""
		if k.Family == 4 {
			addr = net.IP(k.Addr[:4]).String()
		} else {
			addr = net.IP(k.Addr[:]).String()
		}
		out = append(out, models.ShieldSourceStat{
			Family:     familyName(k.Family),
			Class:      shieldClassName(uint32(k.ClassID)),
			Address:    addr,
			Denied:     v.Denied,
			LastSeenNS: v.LastNS,
			Attempts:   v.Attempts,
		})
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	// Sort by Attempts, not Denied: Attempts >= Denied always (every denied
	// packet was first counted as an attempt), so this never loses a
	// high-Denied source and also keeps high-Attempts/low-Denied sources
	// (e.g. audit mode, or a class whose pps threshold is disabled) that a
	// Denied-only sort would truncate away before the controller ever sees them.
	sort.Slice(out, func(i, j int) bool { return out[i].Attempts > out[j].Attempts })
	if len(out) > 200 {
		out = out[:200]
	}
	return out, nil
}

// readInterfaceFlowStats decodes iface_flow_stats using the same raw
// byte-offset convention as flow_stats/workload_flow_stats above:
// key = ifindex(4, native) + flow_key(40: family,direction,hook,protocol
// each 1 byte, src_port/dst_port 2 bytes network order, src_addr/dst_addr
// 16 bytes each) = 44 bytes; value = flow_value's 4 uint64 fields = 32
// bytes. Interface names are resolved agent-side from a fresh
// net.Interfaces() snapshot rather than pushing an ifindex->name map
// into BPF, since the agent already has this for free.
func (a *Agent) readInterfaceFlowStats() ([]models.InterfaceFlowStat, error) {
	m := a.collection.Maps["iface_flow_stats"]
	if m == nil {
		return nil, nil
	}
	ifNames := map[uint32]string{}
	if ifs, err := net.Interfaces(); err == nil {
		for _, it := range ifs {
			ifNames[uint32(it.Index)] = it.Name
		}
	}
	var k [44]byte
	var v [32]byte
	out := make([]models.InterfaceFlowStat, 0, 256)
	it := m.Iterate()
	for it.Next(&k, &v) {
		ifIndex := native.Uint32(k[0:4])
		family := k[4]
		src, dst := "", ""
		if family == 4 {
			src = net.IP(k[12:16]).String()
			dst = net.IP(k[28:32]).String()
		} else if family == 6 {
			src = net.IP(k[12:28]).String()
			dst = net.IP(k[28:44]).String()
		}
		out = append(out, models.InterfaceFlowStat{
			IfIndex: ifIndex, Interface: ifNames[ifIndex],
			Family: familyName(family), Direction: dirName(k[5]), Protocol: protoName(k[7]),
			SourceIP: src, DestinationIP: dst,
			SourcePort: binary.BigEndian.Uint16(k[8:10]), DestinationPort: binary.BigEndian.Uint16(k[10:12]),
			Packets: native.Uint64(v[0:8]), Bytes: native.Uint64(v[8:16]), Blocked: native.Uint64(v[16:24]), LastSeenNS: native.Uint64(v[24:32]),
		})
		if len(out) >= 2000 {
			break
		}
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Packets > out[j].Packets })
	return out, nil
}

func (a *Agent) applyShield(cfg *models.ShieldConfig) error {
	m := a.collection.Maps["shield_cfg"]
	if m == nil {
		return nil
	}
	type raw struct {
		Generation   uint32
		Mode         uint32
		ProtectAll   uint32
		SynPPS       uint32
		UDPPPS       uint32
		ICMPPPS      uint32
		OtherPPS     uint32
		BurstSeconds uint32
	}
	var r raw
	if cfg != nil {
		r.Generation = cfg.Generation
		if r.Generation == 0 {
			r.Generation = 1
		}
		switch strings.ToLower(cfg.Mode) {
		case "audit":
			r.Mode = 1
		case "enforce":
			r.Mode = 2
		}
		if cfg.ProtectAll {
			r.ProtectAll = 1
		}
		r.SynPPS, r.UDPPPS, r.ICMPPPS, r.OtherPPS = cfg.SynPPS, cfg.UDPPPS, cfg.ICMPPPS, cfg.OtherPPS
		r.BurstSeconds = cfg.BurstSeconds
		if r.BurstSeconds == 0 {
			r.BurstSeconds = 2
		}
	}
	if err := m.Put(uint32(0), r); err != nil {
		return err
	}
	pm := a.collection.Maps["shield_protected4"]
	if pm == nil || cfg == nil {
		return nil
	}
	var k struct {
		Generation uint32
		Addr       uint32
	}
	var v uint8
	var keys []struct {
		Generation uint32
		Addr       uint32
	}
	it := pm.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = pm.Delete(x)
	}
	for _, s := range cfg.ProtectedIPv4 {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			continue
		}
		var q struct {
			Generation uint32
			Addr       uint32
		}
		q.Generation = r.Generation
		q.Addr = native.Uint32(ip.To4())
		if err := pm.Put(q, uint8(1)); err != nil {
			return err
		}
	}
	if pm6 := a.collection.Maps["shield_protected6"]; pm6 != nil {
		var k6 struct {
			Generation uint32
			Addr       [16]byte
		}
		var v6 uint8
		var keys6 []struct {
			Generation uint32
			Addr       [16]byte
		}
		it6 := pm6.Iterate()
		for it6.Next(&k6, &v6) {
			keys6 = append(keys6, k6)
		}
		for _, x := range keys6 {
			_ = pm6.Delete(x)
		}
		for _, s := range cfg.ProtectedIPv6 {
			ip := net.ParseIP(s)
			if ip == nil || ip.To4() != nil {
				continue
			}
			var q6 struct {
				Generation uint32
				Addr       [16]byte
			}
			q6.Generation = r.Generation
			copy(q6.Addr[:], ip.To16())
			if err := pm6.Put(q6, uint8(1)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *Agent) applyNetPol(cfg models.EBPFFastPathConfig) error {
	en := a.collection.Maps["netpol_enabled"]
	dm := a.collection.Maps["netpol_deny4"]
	if en == nil || dm == nil {
		return nil
	}
	on := uint32(0)
	if cfg.NetPolEnabled {
		on = 1
	}
	if err := en.Put(uint32(0), on); err != nil {
		return err
	}
	type key struct {
		CgroupID  uint64
		Peer      uint32
		Port      uint16
		Protocol  uint8
		Direction uint8
	}
	var k key
	var v uint8
	var keys []key
	it := dm.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, x := range keys {
		_ = dm.Delete(x)
	}
	for _, d := range cfg.NetPolDenies {
		ip := net.ParseIP(d.PeerIPv4)
		if ip == nil || ip.To4() == nil {
			continue
		}
		proto := uint8(0)
		switch strings.ToUpper(d.Protocol) {
		case "TCP":
			proto = 6
		case "UDP":
			proto = 17
		}
		dirs := []uint8{1, 2}
		switch strings.ToLower(d.Direction) {
		case "ingress":
			dirs = []uint8{1}
		case "egress":
			dirs = []uint8{2}
		}
		for _, dir := range dirs {
			q := key{CgroupID: d.CgroupID, Peer: native.Uint32(ip.To4()), Port: d.Port, Protocol: proto, Direction: dir}
			if err := dm.Put(q, uint8(1)); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyNetPolV2 resolves each NetPolRule/NetPolDefaultDeny's workload
// selector against this node's cgroups — reusing a.workloadByCgroup, which
// applyWorkloadScopes (called just before this, every sync, unconditionally)
// already refreshed — and writes the v2 maps. Rules are always written
// before default-deny postures, every sync, not just on activation: see
// netpol_v2_lookup4's doc comment in bpf/netra_tc.c for why a workload must
// never be marked default-deny while its allow-rules are incomplete (unlike
// every other race window in this codebase, that direction fails closed).
func (a *Agent) applyNetPolV2(cfg models.EBPFFastPathConfig) error {
	enMap := a.collection.Maps["netpol_v2_enabled"]
	rulesMap := a.collection.Maps["netpol_rules4"]
	defaultMap := a.collection.Maps["netpol_default4"]
	if enMap == nil || rulesMap == nil || defaultMap == nil {
		return nil
	}
	a.workloadMu.RLock()
	resolved := a.workloadByCgroup
	a.workloadMu.RUnlock()

	type ruleKey struct {
		CgroupID  uint64
		Peer      uint32
		Port      uint16
		Protocol  uint8
		Direction uint8
	}
	desired := map[ruleKey]uint8{}
	for _, r := range cfg.NetPolRules {
		// Empty PeerIPv4 is a port-only rule (peer=0 wildcard, matching
		// netpol_v2_lookup4's any-peer fallback step in bpf/netra_tc.c) —
		// the API layer (ebpfNetPolRuleAdd) already guarantees Port != 0
		// whenever PeerIPv4 is empty, so this never silently produces a
		// no-op rule with neither field set.
		var peer uint32
		if r.PeerIPv4 != "" {
			ip := net.ParseIP(r.PeerIPv4)
			if ip == nil || ip.To4() == nil {
				continue
			}
			peer = native.Uint32(ip.To4())
		}
		// netpol_v2_lookup4 compares this key's raw bytes against .port
		// (bpf/netra_tc.c), which is copied verbatim from the packet's
		// big-endian wire bytes with no byte-swap. ruleKey is a typed Go
		// struct, so cilium/ebpf marshals Port using the host's native
		// (little-endian) byte order — storing r.Port's decimal value
		// directly would therefore never match a real, non-palindromic
		// port (e.g. 443) on any little-endian host. Round-tripping
		// through a big-endian buffer then native.Uint16, mirroring the
		// Peer field's native.Uint32(ip.To4()) trick two lines up, makes
		// the final marshaled bytes equal the wire-order bytes instead.
		var portBE [2]byte
		binary.BigEndian.PutUint16(portBE[:], r.Port)
		port := native.Uint16(portBE[:])
		proto := uint8(0)
		switch strings.ToUpper(r.Protocol) {
		case "TCP":
			proto = 6
		case "UDP":
			proto = 17
		}
		dirs := []uint8{1, 2}
		switch strings.ToLower(r.Direction) {
		case "ingress":
			dirs = []uint8{1}
		case "egress":
			dirs = []uint8{2}
		}
		action := uint8(0)
		if strings.EqualFold(r.Action, "deny") {
			action = 1
		}
		for cg, w := range resolved {
			if !workload.Match(r.Selector, w) {
				continue
			}
			for _, dir := range dirs {
				desired[ruleKey{CgroupID: cg, Peer: peer, Port: port, Protocol: proto, Direction: dir}] = action
			}
		}
	}
	if err := replaceMapFull(rulesMap, desired); err != nil {
		return err
	}

	now := time.Now()
	postures := map[uint64]uint8{}
	for _, d := range cfg.NetPolDefaultDenies {
		if d.EnabledUntil != nil && now.After(*d.EnabledUntil) {
			continue
		}
		for cg, w := range resolved {
			if workload.Match(d.Selector, w) {
				postures[cg] = 1
			}
		}
	}
	if err := replaceMapFull(defaultMap, postures); err != nil {
		return err
	}

	on := uint32(0)
	if cfg.NetPolV2Enabled {
		on = 1
	}
	return enMap.Put(uint32(0), on)
}

// replaceMapFull rewrites a BPF hash map to contain exactly the given
// entries: every desired key is written first, then anything present that
// isn't in desired is deleted — matching this codebase's existing
// full-rebuild-on-sync convention (applyNetPol, applyWorkloadScopes) rather
// than diffing against the previous call's contents.
func replaceMapFull[K comparable, V any](m *ebpf.Map, desired map[K]V) error {
	var existing []K
	var k K
	var v V
	it := m.Iterate()
	for it.Next(&k, &v) {
		existing = append(existing, k)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return err
	}
	for kk, vv := range desired {
		if err := m.Put(kk, vv); err != nil {
			return err
		}
	}
	for _, kk := range existing {
		if _, ok := desired[kk]; !ok {
			_ = m.Delete(kk)
		}
	}
	return nil
}

func parseHexField(s string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimSpace(s), 16, 64)
	return v
}

func readUintFile(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

func (a *Agent) readNodeStack() models.NodeStackStat {
	var out models.NodeStackStat
	if b, err := os.ReadFile("/proc/net/softnet_stat"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			out.SoftnetProcessed += parseHexField(fields[0])
			out.SoftnetDropped += parseHexField(fields[1])
			out.SoftnetTimeSqueeze += parseHexField(fields[2])
		}
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, it := range ifs {
		if it.Flags&net.FlagLoopback != 0 {
			continue
		}
		base := filepath.Join("/sys/class/net", it.Name, "statistics")
		out.Interfaces = append(out.Interfaces, models.InterfaceStackStat{
			Name:        it.Name,
			RXDropped:   readUintFile(filepath.Join(base, "rx_dropped")),
			TXDropped:   readUintFile(filepath.Join(base, "tx_dropped")),
			RXErrors:    readUintFile(filepath.Join(base, "rx_errors")),
			TXErrors:    readUintFile(filepath.Join(base, "tx_errors")),
			RXMissed:    readUintFile(filepath.Join(base, "rx_missed_errors")),
			RXNoHandler: readUintFile(filepath.Join(base, "rx_nohandler")),
		})
	}
	sort.Slice(out.Interfaces, func(i, j int) bool { return out.Interfaces[i].Name < out.Interfaces[j].Name })
	return out
}

// monotonicNowNS reads CLOCK_MONOTONIC — the same clock source
// bpf_ktime_get_ns() reads in the kernel (see bpf/netra_capture.c) — so a
// desired capture's wall-clock ExpiresAt can be translated into a deadline
// the kernel-side belt-and-suspenders check can compare itself against.
// This is deliberately not derived from time.Now() (wall clock), which can
// jump on NTP correction; CLOCK_MONOTONIC cannot.
func monotonicNowNS() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec), nil
}

// buildCaptureSpecValue translates an operator-facing models.CaptureSpec
// into capture.SpecValue for writing into the capture_spec BPF map — the
// same "local raw struct mirrors the map ABI" pattern applyShield already
// uses for shield_cfg.
func buildCaptureSpecValue(spec models.CaptureSpec) (capture.SpecValue, error) {
	v := capture.SpecValue{Enabled: 1, Port: spec.Port, SnapLen: spec.SnapLen, MaxPPS: spec.MaxPPS}
	switch strings.ToLower(strings.TrimSpace(spec.Protocol)) {
	case "", "any":
	case "tcp":
		v.Protocol = 6
	case "udp":
		v.Protocol = 17
	case "icmp":
		v.Protocol = 1
	case "icmpv6":
		v.Protocol = 58
	default:
		return v, fmt.Errorf("unsupported capture protocol %q", spec.Protocol)
	}
	if spec.Host != "" {
		ip := net.ParseIP(spec.Host)
		if ip == nil {
			return v, fmt.Errorf("invalid capture host %q", spec.Host)
		}
		if ip4 := ip.To4(); ip4 != nil {
			v.Family = 4
			copy(v.Host[:4], ip4)
		} else {
			v.Family = 6
			copy(v.Host[:], ip.To16())
		}
	}
	until := time.Until(spec.ExpiresAt)
	if until <= 0 {
		until = time.Second // already at/past deadline; let the userspace reconcile on the next tick actually clear it
	}
	if now, err := monotonicNowNS(); err == nil {
		v.ExpiresNS = now + uint64(until.Nanoseconds())
	}
	return v, nil
}

// applyCapture reconciles the one desired capture session (nil = none) for
// this node into either the eBPF capture_spec map or an AF_PACKET session
// (internal/afcapture), and the agent→controller streaming connection.
// Called unconditionally on every syncAndReport tick (see there for why).
// A no-op when desired is unchanged from a.activeCapture, so a steady-state
// capture doesn't restart its stream every 3 seconds.
//
// NETRA_CAPTURE (see attachCapture) only gates whether the eBPF capture
// object/collection/links are loaded at all; it has no effect on
// backend: "afpacket" sessions, which need no BPF object whatsoever, so
// the capture_spec-map-unavailable guard below must never apply to them.
func (a *Agent) applyCapture(ctx context.Context, desired *models.CaptureSpec) error {
	if desired == nil {
		if a.activeCapture == nil {
			return nil
		}
		a.stopCaptureStream()
		a.activeCapture = nil
		a.captureBackendErr = ""
		if m := a.captureMap("capture_spec"); m != nil {
			return m.Put(uint32(0), capture.SpecValue{})
		}
		return nil
	}
	if a.activeCapture != nil && *a.activeCapture == *desired {
		return nil
	}
	value, err := buildCaptureSpecValue(*desired)
	if err != nil {
		return err
	}
	backendName, err := models.NormalizeCaptureBackend(desired.Backend)
	if err != nil {
		return err
	}
	if backendName == models.CaptureBackendEBPF {
		m := a.captureMap("capture_spec")
		if m == nil {
			a.captureBackendErr = "ebpf:capture_spec map unavailable"
			return fmt.Errorf("capture_spec map unavailable (packet-capture engine not attached on this node)")
		}
		if err := m.Put(uint32(0), value); err != nil {
			return err
		}
		if rate := a.captureMap("capture_rate"); rate != nil {
			_ = rate.Put(uint32(0), capture.RateValue{}) // fresh counters for the new session
		}
	}
	a.stopCaptureStream() // in case this is a mid-flight filter change, not a fresh start
	d := *desired
	if err := a.startCaptureStream(ctx, d, value); err != nil {
		return err
	}
	a.activeCapture = &d
	return nil
}

func (a *Agent) captureMap(name string) *ebpf.Map {
	if a.captureCollection == nil {
		return nil
	}
	return a.captureCollection.Maps[name]
}

// captureBackend is implemented once per capture backend — the eBPF
// ringbuf path (ringbufCaptureBackend, below) and internal/afcapture's
// *Session both satisfy it already, with no adapter needed for the latter.
// runCaptureStream's WS-dial/encode/write loop is backend-agnostic and
// shared: only frame production differs between backends.
type captureBackend interface {
	Frames() <-chan capture.Frame
	Close() error
}

// ringbufCaptureBackend adapts bpf/netra_capture.c's capture_events
// ringbuf.Reader to the captureBackend shape — this is the existing eBPF
// path's frame production, extracted essentially verbatim from what used
// to be runCaptureStream's own read loop, so the already-shipped,
// already-bug-fixed (v0.27.71) WS-streaming logic in runCaptureStream
// itself stays untouched by this refactor.
type ringbufCaptureBackend struct {
	reader *ringbuf.Reader
	frames chan capture.Frame
	log    *slog.Logger
}

func newRingbufCaptureBackend(m *ebpf.Map, log *slog.Logger) (*ringbufCaptureBackend, error) {
	reader, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, err
	}
	b := &ringbufCaptureBackend{reader: reader, frames: make(chan capture.Frame, 256), log: log}
	go b.run()
	return b, nil
}

func (b *ringbufCaptureBackend) run() {
	defer close(b.frames)
	for {
		record, err := b.reader.Read()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrClosed) {
				b.log.Warn("read capture ring buffer", "error", err)
			}
			return
		}
		ev, err := capture.DecodeRingbufRecord(record.RawSample)
		if err != nil {
			continue
		}
		b.frames <- capture.Frame{
			ObservedAtUnixNano: time.Now().UnixNano(),
			OrigLen:            ev.OrigLen,
			Direction:          ev.Direction,
			Family:             ev.Family,
			Protocol:           ev.Protocol,
			Data:               ev.Data,
		}
	}
}

func (b *ringbufCaptureBackend) Frames() <-chan capture.Frame { return b.frames }
func (b *ringbufCaptureBackend) Close() error                 { return b.reader.Close() }

// startCaptureStream launches the streaming goroutine for the given
// backend and desired spec's already-normalized Backend field.
// NETRA_CAPTURE (see attachCapture) only gates whether the eBPF capture
// object/collection/links are loaded at all; it has no effect on
// backend: "afpacket" sessions, which need no BPF object whatsoever — see
// applyCapture's own doc comment for the same cross-reference.
func (a *Agent) startCaptureStream(parentCtx context.Context, desired models.CaptureSpec, value capture.SpecValue) error {
	ctx, cancel := context.WithCancel(parentCtx)
	backendName, err := models.NormalizeCaptureBackend(desired.Backend)
	if err != nil {
		cancel()
		return err
	}
	var be captureBackend
	switch backendName {
	case models.CaptureBackendAFPacket:
		if !afcapture.Available() {
			cancel()
			a.captureBackendErr = "afpacket:CAP_NET_RAW"
			return fmt.Errorf("AF_PACKET capture unavailable on this node (CAP_NET_RAW probe failed)")
		}
		sess, err := afcapture.Open(ctx, a.interfaces, value)
		if err != nil {
			cancel()
			a.captureBackendErr = "afpacket:" + err.Error()
			return err
		}
		be = sess
	default: // "ebpf"
		m := a.captureMap("capture_events")
		if m == nil {
			cancel()
			a.captureBackendErr = "ebpf:capture_events map unavailable"
			return fmt.Errorf("capture_events map unavailable (packet-capture engine not attached on this node)")
		}
		rb, err := newRingbufCaptureBackend(m, a.log)
		if err != nil {
			cancel()
			a.captureBackendErr = "ebpf:" + err.Error()
			return err
		}
		be = rb
	}
	a.captureBackendErr = ""
	a.captureCancel = cancel
	go a.runCaptureStream(ctx, be)
	return nil
}

func (a *Agent) stopCaptureStream() {
	if a.captureCancel != nil {
		a.captureCancel()
		a.captureCancel = nil
	}
}

// runCaptureStream drains be (either backend — see captureBackend) and
// forwards each frame over an agent-initiated WebSocket to the controller
// (internal/api/capture.go's agentCaptureStream handler), which relays
// frames byte-for-byte to any browser watching this node. This loop itself
// is backend-agnostic and intentionally unchanged from before the
// eBPF/AF_PACKET dispatch was introduced — only frame production (be)
// differs between backends; the WS dial/encode/write logic here is the
// same already-shipped, already-bug-fixed (v0.27.71 TLS-skip-verify fix)
// code path regardless of which backend is running. Exits when ctx is
// cancelled (a.stopCaptureStream, called on config change or agent
// shutdown), be's Frames() channel closes, or the connection fails.
func (a *Agent) runCaptureStream(ctx context.Context, be captureBackend) {
	defer be.Close()
	go func() { <-ctx.Done(); _ = be.Close() }()

	wsURL := strings.NewReplacer("https://", "wss://", "http://", "ws://").Replace(a.server) +
		"/api/v1/agents/capture/stream?node=" + url.QueryEscape(a.node)
	header := http.Header{}
	if a.key != "" {
		header.Set("X-Netra-Agent-Key", a.key)
	}
	conn, _, err := a.wsDialer.DialContext(ctx, wsURL, header)
	if err != nil {
		a.log.Error("dial capture stream", "error", err)
		return
	}
	defer conn.Close()

	for {
		frame, ok := <-be.Frames()
		if !ok {
			return
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, capture.EncodeFrame(frame)); err != nil {
			if ctx.Err() == nil {
				a.log.Warn("write capture frame", "error", err)
			}
			return
		}
	}
}

func (a *Agent) report(ctx context.Context, r models.AgentReport) error {
	b, _ := json.Marshal(r)
	req, _ := http.NewRequestWithContext(ctx, "POST", a.server+"/api/v1/agents/report", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if a.key != "" {
		req.Header.Set("X-Netra-Agent-Key", a.key)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		x, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("report: %s %s", resp.Status, x)
	}
	return nil
}

func protoName(v byte) string {
	switch v {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMPv6"
	default:
		return strconv.Itoa(int(v))
	}
}
func dirName(v byte) string {
	if v == 1 {
		return "ingress"
	}
	if v == 2 {
		return "egress"
	}
	return "unknown"
}
func hookName(v byte) string {
	switch v {
	case 1:
		return "tcx"
	case 2:
		return "cgroup"
	case 3:
		return "xdp"
	case 4:
		return "socket"
	case 5:
		return "sockops"
	default:
		return "unknown"
	}
}
func familyName(v byte) string {
	if v == 4 {
		return "IPv4"
	}
	if v == 6 {
		return "IPv6"
	}
	return "unknown"
}
func actionName(v byte) string {
	if v == 1 {
		return "blocked"
	}
	return "observed"
}
func eventName(v byte) string {
	switch v {
	case 1:
		return "flow"
	case 2:
		return "dns"
	case 3:
		return "connect"
	case 4:
		return "block"
	case 5:
		return "dns-response"
	case 6:
		return "tcp-health"
	default:
		return "event"
	}
}
func reasonName(v byte) string {
	switch v {
	case 1:
		return "exact-ip"
	case 2:
		return "cidr"
	case 3:
		return "port"
	case 4:
		return "uid"
	case 5:
		return "rate-limit"
	case 6:
		return "dns"
	case 7:
		return "process"
	case 8:
		return "tls-sni"
	case 9:
		return "netpol"
	case 10:
		return "netpol-rule"
	case 11:
		return "netpol-default-deny"
	case 12:
		return "conn-rate-limit"
	case 13:
		return "byte-rate-limit"
	case 14:
		return "capability"
	default:
		return ""
	}
}
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// mentionsAny reports whether msg names any of names — used to tell whether
// a collection-load failure was caused specifically by one of the L7 cgroup
// programs (safe to retry without them) rather than something else entirely
// (a real failure that retrying blind would only mask).
func mentionsAny(msg string, names []string) bool {
	for _, n := range names {
		if strings.Contains(msg, n) {
			return true
		}
	}
	return false
}
func envBool(k string, d bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return d
	}
	return b
}
func splitCSV(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
func hostname() string { h, _ := os.Hostname(); return h }
func envDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}

// attachTCPEvents loads bpf/netra_tcpevents.c and attaches its four tracepoint
// programs. It follows attachTLSFP's convention: NETRA_TCP_EVENTS=auto (default)
// degrades to "no TCP events" with a warning; off skips; required fails startup.
//
// Unlike the other sensors it does not assume a kernel layout: each
// tracepoint's record offsets come from the running kernel's own format file
// (internal/tpformat), and a sensor whose layout cannot be established is left
// out with the reason reported rather than attached blind.
func (a *Agent) attachTCPEvents() error {
	mode := strings.ToLower(env("NETRA_TCP_EVENTS", "auto")) // auto|off|required
	if mode == "off" {
		a.log.Info("TCP event tracepoints skipped by NETRA_TCP_EVENTS=off")
		return nil
	}
	sensor, err := tcpevents.Load(tcpevents.Options{ObjectPath: a.tcpEventsObject, Log: a.log})
	if err != nil {
		if mode == "required" {
			return fmt.Errorf("TCP event tracepoints (NETRA_TCP_EVENTS=required): %w", err)
		}
		a.log.Warn("TCP event tracepoints unavailable; continuing without them", "object", a.tcpEventsObject, "error", err)
		return nil
	}
	a.tcpEvents = sensor
	for _, tp := range tcpevents.Tracepoints {
		for _, name := range sensor.Attached() {
			if name == tp.Name {
				a.hooks = append(a.hooks, "tracepoint:"+tp.Group+"/"+tp.Event)
				a.markAttached(tp.Program)
			}
		}
	}
	a.log.Info("TCP event tracepoints attached", "sensors", sensor.Attached(), "skipped", sensor.Skipped())
	return nil
}

// attachDropInfo loads bpf/netra_dropinfo.c and attaches its skb:kfree_skb
// program. NETRA_DROP_INFO=auto (default) degrades to "unavailable" with the
// reason reported; off skips; required fails startup.
//
// It is the one sensor that needs kernel BTF (sk_buff offsets are relocated
// against /sys/kernel/btf/vmlinux); a kernel without it costs only this feature.
func (a *Agent) attachDropInfo() error {
	mode := strings.ToLower(env("NETRA_DROP_INFO", "auto")) // auto|off|required
	if mode == "off" {
		a.log.Info("drop attribution skipped by NETRA_DROP_INFO=off")
		return nil
	}
	sensor, err := dropinfo.Load(dropinfo.Options{ObjectPath: a.dropInfoObject, Log: a.log})
	if err != nil {
		if mode == "required" {
			return fmt.Errorf("drop attribution (NETRA_DROP_INFO=required): %w", err)
		}
		a.dropInfoWhy = err.Error()
		a.log.Warn("drop attribution unavailable; continuing without it", "object", a.dropInfoObject, "error", err)
		return nil
	}
	a.dropInfo = sensor
	a.hooks = append(a.hooks, "tracepoint:"+dropinfo.TPGroup+"/"+dropinfo.TPEvent)
	a.markAttached("netra_drop_info")
	a.log.Info("drop attribution attached", "tracepoint", dropinfo.TPGroup+":"+dropinfo.TPEvent)
	return nil
}

// attachListenQueues enables accept-queue sampling. NETRA_LISTEN_QUEUES=auto
// (default) or off. It needs no BPF and no privilege beyond the host network
// namespace, so there is no "required": a read failure is reported per sample.
func (a *Agent) attachListenQueues() {
	if strings.ToLower(env("NETRA_LISTEN_QUEUES", "auto")) == "off" {
		a.log.Info("listen queue sampling skipped by NETRA_LISTEN_QUEUES=off")
		return
	}
	a.listenQ = &listenq.Sampler{}
}

// listenQueueTop bounds the listener list in each report.
const listenQueueTop = 20

// readListenQueues samples once. nil means off; a failed read is reported as
// Unavailable so the controller can tell "off" from "cannot read the sockets".
func (a *Agent) readListenQueues() *models.ListenQueueSummary {
	if a.listenQ == nil {
		return nil
	}
	sn, err := a.listenQ.Sample(listenQueueTop)
	if err != nil {
		if !a.listenQWarned {
			a.listenQWarned = true
			a.log.Warn("listen queue sampling failed", "error", err)
		}
		why := err.Error()
		if len(why) > maxWhy {
			why = why[:maxWhy]
		}
		return &models.ListenQueueSummary{Unavailable: why}
	}
	a.listenQWarned = false
	out := &models.ListenQueueSummary{
		Listeners: sn.Listeners, Full: sn.Full, Saturated: sn.Saturated, SynRecv: sn.SynRecv,
		Samples: sn.Samples, Buckets: sn.Buckets,
	}
	for _, e := range sn.Top {
		out.Top = append(out.Top, models.ListenQueueEntry{
			Family: e.Family, Addr: e.Addr, Port: e.Port, Queue: e.Queue, Max: e.Max,
			SynRecv: e.SynRecv, Peak: e.Peak, PeakPct: e.PeakPct,
		})
	}
	return out
}

// Bounds on the drop lists in each report.
const (
	dropInfoTopFlows = 50
	dropInfoTopSites = 30
)

// maxWhy bounds the reason text shipped in a report.
const maxWhy = 300

// readDropInfo returns nil when the sensor is off. When it tried and could not
// load it returns a summary saying why, so the controller can tell "off" from
// "unavailable on this kernel". A read failure is logged, not fatal: this is a
// diagnostic side channel and must not stop the rest of the report.
func (a *Agent) readDropInfo() *models.DropInfoSummary {
	if a.dropInfo == nil {
		if a.dropInfoWhy == "" {
			return nil
		}
		why := a.dropInfoWhy
		if len(why) > maxWhy {
			why = why[:maxWhy]
		}
		return &models.DropInfoSummary{Unavailable: why}
	}
	sn, err := a.dropInfo.Snapshot(dropInfoTopFlows, dropInfoTopSites)
	if err != nil {
		a.log.Warn("read drop info", "error", err)
		return nil
	}
	out := &models.DropInfoSummary{
		Attached: sn.Attached, Reasons: sn.Reasons,
		Totals: models.DropInfoTotals{
			Drops: sn.Totals.Drops, WithTuple: sn.Totals.WithTuple, NoTuple: sn.Totals.NoTuple,
			NoHeader: sn.Totals.NoHeader, ReadErrors: sn.Totals.ReadError, MapFull: sn.Totals.MapFull,
		},
	}
	for _, s := range sn.Sites {
		out.Sites = append(out.Sites, models.DropInfoSite{Reason: s.Reason, Location: s.Location, Count: s.Count})
	}
	for _, f := range sn.Flows {
		out.Flows = append(out.Flows, models.DropInfoFlow{
			Family: f.Family, Proto: f.Proto, Src: f.Src, Dst: f.Dst, SrcPort: f.SrcPort, DstPort: f.DstPort,
			Reason: f.Reason, Count: f.Count, Location: f.Location, LastSeenNS: f.LastSeenNS,
		})
	}
	return out
}

// tcpEventsTopFlows bounds the flow list in each report.
const tcpEventsTopFlows = 50

// readTCPEvents returns nil when the sensors never attached or a read fails
// (a read failure is logged, not fatal: this is a diagnostic side channel and
// must not stop the rest of the report).
func (a *Agent) readTCPEvents() *models.TCPEventsSummary {
	if a.tcpEvents == nil {
		return nil
	}
	sn, err := a.tcpEvents.Snapshot(tcpEventsTopFlows)
	if err != nil {
		a.log.Warn("read TCP events", "error", err)
		return nil
	}
	out := &models.TCPEventsSummary{
		Attached: sn.Attached, Skipped: sn.Skipped,
		Totals: models.TCPEventTotals{
			Retransmits: sn.Totals.Retransmits, RSTSent: sn.Totals.RSTSent, RSTReceived: sn.Totals.RSTReceived,
			StateTransitions: sn.Totals.StateTransitions, ReadErrors: sn.Totals.ReadErrors,
			BadFamily: sn.Totals.BadFamily, MapFull: sn.Totals.MapFull,
		},
	}
	for _, t := range sn.Transitions {
		out.Transitions = append(out.Transitions, models.TCPStateTransition{From: t.From, To: t.To, Count: t.Count})
	}
	for _, f := range sn.Flows {
		out.Flows = append(out.Flows, models.TCPEventFlow{
			Family: f.Family, Src: f.Src, Dst: f.Dst, SrcPort: f.SrcPort, DstPort: f.DstPort,
			Retransmits: f.Retransmits, RSTSent: f.RSTSent, RSTReceived: f.RSTReceived, LastSeenNS: f.LastSeenNS,
		})
	}
	return out
}
