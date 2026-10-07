// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/automitigate"
	"github.com/zyvorai/netra/internal/capdrift"
	"github.com/zyvorai/netra/internal/capture"
	"github.com/zyvorai/netra/internal/chatops"
	"github.com/zyvorai/netra/internal/detective"
	"github.com/zyvorai/netra/internal/dnsdetect"
	"github.com/zyvorai/netra/internal/dropdiag"
	"github.com/zyvorai/netra/internal/exehash"
	"github.com/zyvorai/netra/internal/flowstats"
	"github.com/zyvorai/netra/internal/gitops"
	"github.com/zyvorai/netra/internal/health"
	"github.com/zyvorai/netra/internal/hubble"
	"github.com/zyvorai/netra/internal/insights"
	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/ipv6diag"
	"github.com/zyvorai/netra/internal/kerneldiag"
	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/l7"
	"github.com/zyvorai/netra/internal/metricalert"
	"github.com/zyvorai/netra/internal/metricexport"
	"github.com/zyvorai/netra/internal/metricstream"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/mtls"
	"github.com/zyvorai/netra/internal/nsdrift"
	"github.com/zyvorai/netra/internal/observability"
	"github.com/zyvorai/netra/internal/oidcauth"
	"github.com/zyvorai/netra/internal/pathdiag"
	"github.com/zyvorai/netra/internal/policy"
	"github.com/zyvorai/netra/internal/scandetect"
	"github.com/zyvorai/netra/internal/shielddiag"
	"github.com/zyvorai/netra/internal/store"
	"github.com/zyvorai/netra/internal/sysctlaudit"
	"github.com/zyvorai/netra/internal/tlsfp"
	"github.com/zyvorai/netra/internal/workload"
	"github.com/zyvorai/netra/internal/workloadobs"
)

type Server struct {
	log                 *slog.Logger
	kube                *kube.Client
	hubble              *hubble.Client
	store               *store.Store
	gitops              *gitops.Reconciler
	chatopsHandler      http.Handler
	chatopsTeamsHandler http.Handler
	apiKey              string
	agentKey            string
	agentMTLS           mtls.Mode // agent client-certificate policy (NETRA_AGENT_MTLS)
	chatopsAPIKey       string
	metricsToken        string
	oidc                *oidcauth.Verifier
	wobs                *workloadobs.Observer
	webDir              string
	agentStaleAfter     time.Duration
	requirePreflight    bool
	ciliumEnabled       bool
	consoleEnabled      bool
	metricsData         *telemetry
	captureHub          *captureHub
	artifacts           *capture.ArtifactStore
	dnsDetector         *dnsdetect.Detector
	scanDetector        *scandetect.Detector
	intelFeed           *intel.Feed
	autoMitigate        *automitigate.Engine
	tlsFP               *tlsfp.Detector
	workloadInventory   *workloadInventoryCache
	metricsHub          *metricstream.Hub
	metricAlerts        *metricalert.Engine
	metricExporters     func() []metricexport.Status
}

func New(log *slog.Logger, k *kube.Client, h *hubble.Client, st *store.Store) *Server {
	staleAfter := 45 * time.Second
	if raw := os.Getenv("NETRA_AGENT_STALE_AFTER"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d >= 5*time.Second {
			staleAfter = d
		}
	}
	requirePreflight := !strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_REQUIRE_PREFLIGHT")), "false")
	ciliumEnabled := strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_CILIUM_ENABLED")), "true")
	consoleEnabled := strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_WORKLOAD_CONSOLE")), "true")
	feed, feedErr := intel.Open(strings.TrimSpace(os.Getenv("NETRA_INTEL_STATE_PATH")))
	if feedErr != nil {
		log.Warn("intel journal unavailable", "error", feedErr)
	}
	s := &Server{log: log, kube: k, hubble: h, store: st, apiKey: os.Getenv("NETRA_API_KEY"), agentKey: os.Getenv("NETRA_AGENT_KEY"), webDir: os.Getenv("NETRA_WEB_DIR"), agentStaleAfter: staleAfter, requirePreflight: requirePreflight, ciliumEnabled: ciliumEnabled, consoleEnabled: consoleEnabled, metricsData: &telemetry{}, captureHub: newCaptureHub(), intelFeed: feed, tlsFP: tlsfp.NewDetector(2048), workloadInventory: newWorkloadInventoryCache()}

	// netrad refuses to start on a bad NETRA_AGENT_MTLS; if this runs anyway, fail
	// closed rather than quietly turning a security setting off.
	mode, modeErr := mtls.ParseMode(os.Getenv("NETRA_AGENT_MTLS"))
	if modeErr != nil {
		log.Error("invalid NETRA_AGENT_MTLS; requiring client certificates", "error", modeErr)
		mode = mtls.Required
	}
	s.agentMTLS = mode

	// ChatOps outbound trust is shared across every provider: every command
	// is a thin HTTP client of this same process's own /api/v1/* endpoints
	// (a real loopback call, never importing handler internals directly),
	// authenticated with its own dedicated key so a compromised Slack/Teams
	// app credential can't be replayed as full operator access.
	s.chatopsAPIKey = os.Getenv("NETRA_CHATOPS_API_KEY")
	s.metricsToken = strings.TrimSpace(os.Getenv("NETRA_METRICS_TOKEN"))
	chatopsTarget := strings.TrimSpace(os.Getenv("NETRA_CHATOPS_TARGET_URL"))
	if chatopsTarget == "" {
		chatopsTarget = "https://127.0.0.1:30870"
	}
	allowChatopsMutations := strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_CHATOPS_ALLOW_MUTATIONS")), "true")

	// ChatOps (Slack) is off unless NETRA_CHATOPS_SIGNING_SECRET is set —
	// inbound requests are verified with that secret, never Netra's own
	// bearer token (Slack can't send it).
	if secret := strings.TrimSpace(os.Getenv("NETRA_CHATOPS_SIGNING_SECRET")); secret != "" {
		s.chatopsHandler = chatops.NewHandler(chatops.Config{
			SigningSecret:  secret,
			AllowMutations: allowChatopsMutations,
			Client:         chatops.NewClient(chatopsTarget, s.chatopsAPIKey),
		})
	}

	// ChatOps (Microsoft Teams) is off unless NETRA_CHATOPS_TEAMS_APP_ID is
	// set — inbound requests are verified as a Bot Framework JWT against
	// that app ID instead of an HMAC secret (see teams_signature.go).
	if appID := strings.TrimSpace(os.Getenv("NETRA_CHATOPS_TEAMS_APP_ID")); appID != "" {
		s.chatopsTeamsHandler = chatops.NewTeamsHandler(chatops.TeamsConfig{
			AppID:          appID,
			AllowMutations: allowChatopsMutations,
			Client:         chatops.NewClient(chatopsTarget, s.chatopsAPIKey),
		})
	}
	return s
}

// WithGitOps attaches a gitops.Reconciler so GET/POST /api/v1/policies/gitops/*
// have something to read/act on — optional, since GitOps is off unless
// NETRA_GITOPS_DIR is set. Returns s for chaining onto New(...).
func (s *Server) WithGitOps(r *gitops.Reconciler) *Server {
	s.gitops = r
	return s
}

// WithDNSDetect attaches the shared *dnsdetect.Detector instance a
// cmd/netrad poller is (or isn't) feeding — optional, since dnsdetect is
// off unless NETRA_DNSDETECT_ENABLED=true. Both the API handler and the
// poller read/write the same pointer, the same "long-lived object shared
// between an HTTP-exposed piece and a background-running piece" shape
// gitops already uses. Returns s for chaining onto New(...).
func (s *Server) WithDNSDetect(d *dnsdetect.Detector) *Server {
	s.dnsDetector = d
	return s
}

// WithScanDetect attaches the shared *scandetect.Detector instance a
// cmd/netrad poller is (or isn't) feeding — optional, since scandetect is
// off unless NETRA_SCANDETECT_ENABLED=true. Same sharing shape as
// WithDNSDetect. Returns s for chaining onto New(...).
func (s *Server) WithScanDetect(d *scandetect.Detector) *Server {
	s.scanDetector = d
	return s
}

// WithAutoMitigate attaches the optional volumetric auto-mitigation engine
// (NETRA_AUTOMITIGATE_ENABLED). Status-only from the API; the engine runs
// in cmd/netrad. Returns s for chaining.
func (s *Server) WithAutoMitigate(e *automitigate.Engine) *Server {
	s.autoMitigate = e
	return s
}

// WithArtifacts attaches the auto-capture PCAP store used by agentCaptureStream,
// GET /api/v1/capture/artifacts/{id}, and .../artifacts/{id}/context.
// Nil disables server-side recording.
func (s *Server) WithArtifacts(a *capture.ArtifactStore) *Server {
	s.artifacts = a
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "service": "netrad", "version": "0.29.0"})
	})
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "service": "netrad", "version": "0.29.0"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "leader": true, "version": "0.29.0"})
	})
	mux.HandleFunc("POST /api/v1/session", s.sessionCreate)
	mux.HandleFunc("DELETE /api/v1/session", s.sessionDelete)
	mux.Handle("GET /metrics", s.metricsAuth(http.HandlerFunc(s.metrics)))
	if s.chatopsHandler != nil {
		// Outside s.auth(...) — Slack can't send our bearer token, it signs
		// requests with its own HMAC scheme instead (verified inside
		// chatops.NewHandler). Still registered on this same mux, so
		// ha.Gate's existing standby-503 behavior covers it for free.
		mux.Handle("POST /chatops/slack", s.chatopsHandler)
	}
	if s.chatopsTeamsHandler != nil {
		// Same reasoning as the Slack route above: outside s.auth(...)
		// since Teams can't send our bearer token either, but on this same
		// mux so ha.Gate's standby-503 behavior covers it too.
		mux.Handle("POST /chatops/teams", s.chatopsTeamsHandler)
	}
	mux.Handle("GET /api/v1/status", s.auth(http.HandlerFunc(s.status)))
	mux.Handle("GET /api/v1/whoami", s.auth(http.HandlerFunc(s.whoami)))
	mux.Handle("GET /api/v1/slo", s.auth(http.HandlerFunc(s.sloStatus)))
	mux.Handle("GET /api/v1/ebpf/tcp-events", s.auth(http.HandlerFunc(s.ebpfTCPEvents)))
	mux.Handle("GET /api/v1/ebpf/drop-info", s.auth(http.HandlerFunc(s.ebpfDropInfo)))
	mux.Handle("GET /api/v1/ebpf/node-isolation", s.auth(http.HandlerFunc(s.nodeIsolationList)))
	mux.Handle("PUT /api/v1/ebpf/node-isolation/{node}", s.auth(http.HandlerFunc(s.nodeIsolationSet)))
	mux.Handle("DELETE /api/v1/ebpf/node-isolation/{node}", s.auth(http.HandlerFunc(s.nodeIsolationClear)))
	mux.Handle("GET /api/v1/listen-queues", s.auth(http.HandlerFunc(s.listenQueues)))
	mux.Handle("GET /api/v1/netlink", s.auth(http.HandlerFunc(s.netlinkChanges)))
	mux.Handle("GET /api/v1/netlink/findings", s.auth(http.HandlerFunc(s.netlinkFindings)))
	mux.Handle("GET /api/v1/ebpf/attachments", s.auth(http.HandlerFunc(s.bpfAttachments)))
	mux.Handle("GET /api/v1/l7/sampled", s.auth(http.HandlerFunc(s.l7Sampled)))
	mux.Handle("GET /api/v1/l7/tls", s.auth(http.HandlerFunc(s.tlsSampled)))
	mux.Handle("GET /api/v1/features", s.auth(http.HandlerFunc(s.listFeatures)))
	mux.Handle("POST /api/v1/features/{id}", s.auth(http.HandlerFunc(s.setFeature)))
	mux.Handle("GET /api/v1/policies", s.auth(s.cilium(http.HandlerFunc(s.listPolicies))))
	mux.Handle("POST /api/v1/policies/build", s.auth(http.HandlerFunc(s.buildPolicy)))
	mux.Handle("POST /api/v1/policies/plan", s.auth(s.cilium(http.HandlerFunc(s.planPolicy))))
	mux.Handle("POST /api/v1/policies/simulate", s.auth(http.HandlerFunc(s.simulatePolicy)))
	mux.Handle("POST /api/v1/policies/apply", s.auth(s.cilium(http.HandlerFunc(s.applyPolicy))))
	mux.Handle("POST /api/v1/policies/lockdown", s.auth(s.cilium(http.HandlerFunc(s.lockdownPolicy))))
	mux.Handle("DELETE /api/v1/policies/lockdown/{namespace}/{name}", s.auth(s.cilium(http.HandlerFunc(s.unlockPolicy))))
	mux.Handle("GET /api/v1/policies/gitops/status", s.auth(http.HandlerFunc(s.gitopsStatus)))
	mux.Handle("POST /api/v1/policies/gitops/resync", s.auth(s.cilium(http.HandlerFunc(s.gitopsResync))))
	mux.Handle("GET /api/v1/policies/history", s.auth(http.HandlerFunc(s.policyHistory)))
	mux.Handle("GET /api/v1/policies/history/export", s.auth(http.HandlerFunc(s.exportPolicyHistory)))
	mux.Handle("POST /api/v1/policies/history/import", s.auth(http.HandlerFunc(s.importPolicyHistory)))
	mux.Handle("POST /api/v1/policies/{namespace}/{name}/rollback/{revision}", s.auth(s.cilium(http.HandlerFunc(s.rollbackPolicy))))
	mux.Handle("DELETE /api/v1/policies/{namespace}/{name}", s.auth(s.cilium(http.HandlerFunc(s.deletePolicy))))
	mux.Handle("GET /api/v1/pods", s.auth(http.HandlerFunc(s.listPods)))
	mux.Handle("GET /api/v1/vms", s.auth(http.HandlerFunc(s.listVMs)))
	mux.Handle("GET /api/v1/workloads/{kind}/{namespace}/{name}", s.auth(http.HandlerFunc(s.workloadDetail)))
	if s.consoleEnabled {
		mux.Handle("GET /api/v1/pods/{namespace}/{name}/logs", s.auth(http.HandlerFunc(s.streamPodLogs)))
		mux.Handle("GET /api/v1/pods/{namespace}/{name}/exec", s.auth(http.HandlerFunc(s.proxyPodExec)))
		mux.Handle("GET /api/v1/vms/{namespace}/{name}/vnc", s.auth(http.HandlerFunc(s.proxyVMVnc)))
	}
	mux.Handle("GET /api/v1/flows/stream", s.auth(http.HandlerFunc(s.streamFlows)))
	mux.Handle("GET /api/v1/flows/summary", s.auth(http.HandlerFunc(s.flowSummary)))
	mux.Handle("GET /api/v1/flows/history", s.auth(http.HandlerFunc(s.flowHistory)))
	mux.Handle("GET /api/v1/drops/explain", s.auth(http.HandlerFunc(s.ebpfDropExplain)))
	mux.Handle("GET /api/v1/ebpf/config", s.authOrAgent(http.HandlerFunc(s.ebpfConfig)))
	mux.Handle("PUT /api/v1/vms/{node}/capture", s.auth(http.HandlerFunc(s.captureStart)))
	mux.Handle("DELETE /api/v1/vms/{node}/capture", s.auth(http.HandlerFunc(s.captureStop)))
	mux.Handle("GET /api/v1/vms/{node}/capture/ws", s.auth(http.HandlerFunc(s.proxyCaptureStream)))
	mux.Handle("GET /api/v1/capture/status", s.auth(http.HandlerFunc(s.captureStatus)))
	mux.Handle("GET /api/v1/capture/history", s.auth(http.HandlerFunc(s.captureHistory)))
	mux.Handle("GET /api/v1/capture/artifacts/{id}/context", s.auth(http.HandlerFunc(s.captureArtifactContext)))
	mux.Handle("GET /api/v1/capture/artifacts/{id}", s.auth(http.HandlerFunc(s.captureArtifactDownload)))
	mux.Handle("POST /api/v1/capture/bulk", s.auth(http.HandlerFunc(s.captureBulkStart)))
	mux.Handle("GET /api/v1/agents/capture/stream", s.agentAuth(http.HandlerFunc(s.agentCaptureStream)))
	mux.Handle("GET /api/v1/ebpf/workloads", s.auth(http.HandlerFunc(s.ebpfWorkloads)))
	mux.Handle("PUT /api/v1/ebpf/scope", s.auth(http.HandlerFunc(s.ebpfScope)))
	mux.Handle("POST /api/v1/ebpf/scope/preview", s.auth(http.HandlerFunc(s.ebpfScopePreview)))
	mux.Handle("GET /api/v1/ebpf/topology", s.auth(http.HandlerFunc(s.ebpfTopology)))
	mux.Handle("PUT /api/v1/ebpf/mode", s.auth(http.HandlerFunc(s.ebpfMode)))
	mux.Handle("POST /api/v1/ebpf/deny", s.auth(http.HandlerFunc(s.ebpfDenyAdd)))
	mux.Handle("POST /api/v1/ebpf/deny/preview", s.auth(http.HandlerFunc(s.ebpfDenyPreview)))
	mux.Handle("DELETE /api/v1/ebpf/deny/{ip}", s.auth(http.HandlerFunc(s.ebpfDenyDelete)))
	mux.Handle("POST /api/v1/ebpf/deny/import", s.auth(http.HandlerFunc(s.ebpfDenyImport)))
	mux.Handle("POST /api/v1/ebpf/allow", s.auth(http.HandlerFunc(s.ebpfAllowAdd)))
	mux.Handle("DELETE /api/v1/ebpf/allow/{ip}", s.auth(http.HandlerFunc(s.ebpfAllowDelete)))
	mux.Handle("POST /api/v1/ebpf/cidr", s.auth(http.HandlerFunc(s.ebpfCIDRAdd)))
	mux.Handle("POST /api/v1/ebpf/cidr/delete", s.auth(http.HandlerFunc(s.ebpfCIDRDelete)))
	mux.Handle("POST /api/v1/ebpf/syn-drop", s.auth(http.HandlerFunc(s.ebpfSynDropAdd)))
	mux.Handle("POST /api/v1/ebpf/syn-drop/delete", s.auth(http.HandlerFunc(s.ebpfSynDropDelete)))
	mux.Handle("POST /api/v1/ebpf/syn-drop-cidr", s.auth(http.HandlerFunc(s.ebpfSynDropCIDRAdd)))
	mux.Handle("POST /api/v1/ebpf/syn-drop-cidr/delete", s.auth(http.HandlerFunc(s.ebpfSynDropCIDRDelete)))
	mux.Handle("POST /api/v1/ebpf/allow-cidr", s.auth(http.HandlerFunc(s.ebpfAllowCIDRAdd)))
	mux.Handle("POST /api/v1/ebpf/allow-cidr/delete", s.auth(http.HandlerFunc(s.ebpfAllowCIDRDelete)))
	mux.Handle("POST /api/v1/ebpf/port", s.auth(http.HandlerFunc(s.ebpfPortAdd)))
	mux.Handle("POST /api/v1/ebpf/port/delete", s.auth(http.HandlerFunc(s.ebpfPortDelete)))
	mux.Handle("POST /api/v1/ebpf/allow-port", s.auth(http.HandlerFunc(s.ebpfAllowPortAdd)))
	mux.Handle("POST /api/v1/ebpf/allow-port/delete", s.auth(http.HandlerFunc(s.ebpfAllowPortDelete)))
	mux.Handle("POST /api/v1/ebpf/uid", s.auth(http.HandlerFunc(s.ebpfUIDAdd)))
	mux.Handle("DELETE /api/v1/ebpf/uid/{uid}", s.auth(http.HandlerFunc(s.ebpfUIDDelete)))
	mux.Handle("POST /api/v1/ebpf/allow-uid", s.auth(http.HandlerFunc(s.ebpfAllowUIDAdd)))
	mux.Handle("DELETE /api/v1/ebpf/allow-uid/{uid}", s.auth(http.HandlerFunc(s.ebpfAllowUIDDelete)))
	mux.Handle("POST /api/v1/ebpf/dns", s.auth(http.HandlerFunc(s.ebpfDNSAdd)))
	mux.Handle("POST /api/v1/ebpf/dns/delete", s.auth(http.HandlerFunc(s.ebpfDNSDelete)))
	mux.Handle("POST /api/v1/ebpf/process", s.auth(http.HandlerFunc(s.ebpfProcessAdd)))
	mux.Handle("POST /api/v1/ebpf/process/delete", s.auth(http.HandlerFunc(s.ebpfProcessDelete)))
	mux.Handle("POST /api/v1/ebpf/capability", s.auth(http.HandlerFunc(s.ebpfCapabilityAdd)))
	mux.Handle("POST /api/v1/ebpf/capability/delete", s.auth(http.HandlerFunc(s.ebpfCapabilityDelete)))
	mux.Handle("POST /api/v1/ebpf/allow-process", s.auth(http.HandlerFunc(s.ebpfAllowProcessAdd)))
	mux.Handle("POST /api/v1/ebpf/allow-process/delete", s.auth(http.HandlerFunc(s.ebpfAllowProcessDelete)))
	mux.Handle("POST /api/v1/ebpf/sni", s.auth(http.HandlerFunc(s.ebpfSNIAdd)))
	mux.Handle("POST /api/v1/ebpf/sni/delete", s.auth(http.HandlerFunc(s.ebpfSNIDelete)))
	mux.Handle("PUT /api/v1/ebpf/rate", s.auth(http.HandlerFunc(s.ebpfRateSet)))
	mux.Handle("DELETE /api/v1/ebpf/rate/{ip}", s.auth(http.HandlerFunc(s.ebpfRateDelete)))
	mux.Handle("PUT /api/v1/ebpf/shield", s.auth(http.HandlerFunc(s.ebpfShieldSet)))
	mux.Handle("PUT /api/v1/ebpf/netpol/config", s.auth(http.HandlerFunc(s.ebpfNetPolConfigSet)))
	mux.Handle("PUT /api/v1/ebpf/netpol/v2/config", s.auth(http.HandlerFunc(s.ebpfNetPolV2ConfigSet)))
	mux.Handle("POST /api/v1/ebpf/netpol/rules", s.auth(http.HandlerFunc(s.ebpfNetPolRuleAdd)))
	mux.Handle("DELETE /api/v1/ebpf/netpol/rules/{id}", s.auth(http.HandlerFunc(s.ebpfNetPolRuleDelete)))
	mux.Handle("POST /api/v1/ebpf/conn-rate-limit", s.auth(http.HandlerFunc(s.ebpfConnRateLimitAdd)))
	mux.Handle("DELETE /api/v1/ebpf/conn-rate-limit/{id}", s.auth(http.HandlerFunc(s.ebpfConnRateLimitDelete)))
	mux.Handle("POST /api/v1/ebpf/netpol/default-deny/plan", s.auth(http.HandlerFunc(s.ebpfNetPolDefaultDenyPlan)))
	mux.Handle("PUT /api/v1/ebpf/netpol/default-deny", s.auth(http.HandlerFunc(s.ebpfNetPolDefaultDenySet)))
	mux.Handle("GET /api/v1/ebpf/rules", s.auth(http.HandlerFunc(s.ebpfRulesList)))
	mux.Handle("GET /api/v1/ebpf/rules/{id}", s.auth(http.HandlerFunc(s.ebpfRuleGet)))
	mux.Handle("PATCH /api/v1/ebpf/rules/{id}", s.auth(http.HandlerFunc(s.ebpfRulePatch)))
	mux.Handle("DELETE /api/v1/ebpf/rules/{id}", s.auth(http.HandlerFunc(s.ebpfRuleDelete)))
	mux.Handle("GET /api/v1/ebpf/rules/{id}/history", s.auth(http.HandlerFunc(s.ebpfRuleHistory)))
	mux.Handle("POST /api/v1/ebpf/rules/{id}/rollback/{revision}", s.auth(http.HandlerFunc(s.ebpfRuleRollback)))
	mux.Handle("GET /api/v1/ebpf/summary", s.auth(http.HandlerFunc(s.ebpfSummary)))
	mux.Handle("GET /api/v1/ebpf/health", s.auth(http.HandlerFunc(s.ebpfHealth)))
	mux.Handle("GET /api/v1/ebpf/capdrift", s.auth(http.HandlerFunc(s.ebpfCapDrift)))
	mux.Handle("GET /api/v1/ebpf/nsdrift", s.auth(http.HandlerFunc(s.ebpfNamespaceDrift)))
	mux.Handle("GET /api/v1/ebpf/exehash", s.auth(http.HandlerFunc(s.ebpfExeHashDrift)))
	mux.Handle("GET /api/v1/ebpf/path", s.auth(http.HandlerFunc(s.ebpfPathDiagnostics)))
	mux.Handle("GET /api/v1/ebpf/drops", s.auth(http.HandlerFunc(s.ebpfDropDiagnostics)))
	mux.Handle("GET /api/v1/ebpf/kernel-network", s.auth(http.HandlerFunc(s.ebpfKernelNetworkDiagnostics)))
	mux.Handle("GET /api/v1/ebpf/kernel-network/sparkline", s.auth(http.HandlerFunc(s.ebpfKernelNetworkSparkline)))
	mux.Handle("GET /api/v1/ebpf/sysctl-audit", s.auth(http.HandlerFunc(s.ebpfSysctlAudit)))
	mux.Handle("GET /api/v1/ebpf/dns-findings", s.auth(http.HandlerFunc(s.ebpfDNSFindings)))
	mux.Handle("GET /api/v1/ebpf/scan-findings", s.auth(http.HandlerFunc(s.ebpfScanFindings)))
	mux.Handle("GET /api/v1/ebpf/ipv6", s.auth(http.HandlerFunc(s.ebpfIPv6Diagnostics)))
	mux.Handle("GET /api/v1/ebpf/shield", s.auth(http.HandlerFunc(s.ebpfShieldDiagnostics)))
	mux.Handle("GET /api/v1/ebpf/interfaces", s.auth(http.HandlerFunc(s.ebpfInterfaceFlows)))
	mux.Handle("GET /api/v1/ebpf/diagnose", s.auth(http.HandlerFunc(s.ebpfDropDetective)))
	mux.Handle("GET /api/v1/ebpf/explain", s.auth(http.HandlerFunc(s.ebpfDropExplain)))
	mux.Handle("GET /api/v1/ebpf/l7", s.auth(http.HandlerFunc(s.ebpfL7)))
	mux.Handle("GET /api/v1/ebpf/capabilities", s.auth(http.HandlerFunc(s.ebpfCapabilities)))
	mux.Handle("GET /api/v1/insights/summary", s.auth(http.HandlerFunc(s.insightsSummary)))
	mux.Handle("GET /api/v1/insights/dependencies", s.auth(http.HandlerFunc(s.insightsDependencies)))
	mux.Handle("GET /api/v1/insights/baseline", s.auth(http.HandlerFunc(s.insightsBaselineGet)))
	mux.Handle("POST /api/v1/insights/baseline", s.auth(http.HandlerFunc(s.insightsBaselineCapture)))
	mux.Handle("DELETE /api/v1/insights/baseline", s.auth(http.HandlerFunc(s.insightsBaselineClear)))
	mux.Handle("GET /api/v1/insights/drift", s.auth(http.HandlerFunc(s.insightsDrift)))
	mux.Handle("GET /api/v1/insights/recommendations", s.auth(http.HandlerFunc(s.insightsRecommendations)))
	mux.Handle("GET /api/v1/insights/zero-trust", s.auth(http.HandlerFunc(s.insightsZeroTrust)))
	mux.Handle("GET /api/v1/insights/microseg", s.auth(http.HandlerFunc(s.insightsMicroseg)))
	mux.Handle("GET /api/v1/insights/shadow-saas", s.auth(http.HandlerFunc(s.insightsShadowSaaS)))
	mux.Handle("GET /api/v1/insights/experience", s.auth(http.HandlerFunc(s.insightsExperience)))
	mux.Handle("GET /api/v1/insights/red", s.auth(http.HandlerFunc(s.insightsRED)))
	mux.Handle("GET /api/v1/insights/traces", s.auth(http.HandlerFunc(s.insightTraces)))
	mux.Handle("GET /api/v1/insights/profiles", s.auth(http.HandlerFunc(s.insightProfiles)))
	mux.Handle("GET /api/v1/insights/workload-events", s.auth(http.HandlerFunc(s.workloadEvents)))
	mux.Handle("GET /api/v1/insights/kernel-notes", s.auth(http.HandlerFunc(s.kernelNotes)))
	mux.Handle("GET /api/v1/insights/destination-risk", s.auth(http.HandlerFunc(s.insightsDestinationRisk)))
	mux.Handle("GET /api/v1/insights/policy-packs", s.auth(http.HandlerFunc(s.insightsPolicyPacks)))
	mux.Handle("GET /api/v1/insights/identity-drafts", s.auth(http.HandlerFunc(s.insightsIdentityDrafts)))
	mux.Handle("GET /api/v1/insights/ech-blind", s.auth(http.HandlerFunc(s.insightsECHBlind)))
	mux.Handle("GET /api/v1/insights/exfil", s.auth(http.HandlerFunc(s.insightsExfil)))
	mux.Handle("GET /api/v1/insights/lateral", s.auth(http.HandlerFunc(s.insightsLateral)))
	mux.Handle("GET /api/v1/insights/category-deny", s.auth(http.HandlerFunc(s.insightsCategoryDeny)))
	mux.Handle("GET /api/v1/insights/rates", s.auth(http.HandlerFunc(s.insightsRates)))
	mux.Handle("GET /api/v1/insights/rate-baseline", s.auth(http.HandlerFunc(s.insightsRateBaselineGet)))
	mux.Handle("POST /api/v1/insights/rate-baseline", s.auth(http.HandlerFunc(s.insightsRateBaselineCapture)))
	mux.Handle("DELETE /api/v1/insights/rate-baseline", s.auth(http.HandlerFunc(s.insightsRateBaselineClear)))
	mux.Handle("GET /api/v1/insights/rate-drift", s.auth(http.HandlerFunc(s.insightsRateDrift)))
	mux.Handle("GET /api/v1/insights/exposure", s.auth(http.HandlerFunc(s.insightsExposure)))
	mux.Handle("GET /api/v1/insights/blast-radius", s.auth(http.HandlerFunc(s.insightsBlastRadius)))
	mux.Handle("GET /api/v1/insights/health-trend", s.auth(http.HandlerFunc(s.insightsHealthTrend)))
	mux.Handle("GET /api/v1/insights/policy-review", s.auth(http.HandlerFunc(s.insightsPolicyReview)))
	mux.Handle("GET /api/v1/insights/new-since-start", s.auth(http.HandlerFunc(s.insightsNewSinceStart)))
	mux.Handle("GET /api/v1/insights/protocol-downgrades", s.auth(http.HandlerFunc(s.insightsProtocolDowngrades)))
	mux.Handle("GET /api/v1/insights/remediations", s.auth(http.HandlerFunc(s.insightsRemediations)))
	mux.Handle("GET /api/v1/agents", s.auth(http.HandlerFunc(s.agents)))
	mux.Handle("GET /api/v1/audit", s.auth(http.HandlerFunc(s.audit)))
	mux.Handle("GET /api/v1/export/audit", s.auth(http.HandlerFunc(s.exportAudit)))
	mux.Handle("GET /api/v1/export/events", s.auth(http.HandlerFunc(s.exportEvents)))
	mux.Handle("GET /api/v1/export/flows", s.auth(http.HandlerFunc(s.exportFlows)))
	mux.Handle("GET /api/v1/export/blocks", s.auth(http.HandlerFunc(s.exportBlocks)))
	mux.Handle("GET /api/v1/export/status", s.auth(http.HandlerFunc(s.exportStatus)))
	mux.Handle("GET /api/v1/report", s.auth(http.HandlerFunc(s.operatorReport)))
	mux.Handle("GET /api/v1/playbooks", s.auth(http.HandlerFunc(s.playbooks)))
	mux.Handle("GET /api/v1/audit/summary", s.auth(http.HandlerFunc(s.auditSummary)))
	mux.Handle("POST /api/v1/intel/preview", s.auth(http.HandlerFunc(s.intelPreview)))
	mux.Handle("GET /api/v1/security/optimizer", s.auth(http.HandlerFunc(s.securityOptimizer)))
	mux.Handle("GET /api/v1/security/incidents", s.auth(http.HandlerFunc(s.securityIncidents)))
	mux.Handle("GET /api/v1/intel/history", s.auth(http.HandlerFunc(s.intelHistory)))
	mux.Handle("POST /api/v1/intel/rollback/{revision}", s.auth(http.HandlerFunc(s.intelRollback)))
	mux.Handle("GET /api/v1/intel/feed", s.auth(http.HandlerFunc(s.intelFeedGet)))
	mux.Handle("PUT /api/v1/intel/feed", s.auth(http.HandlerFunc(s.intelFeedPut)))
	mux.Handle("DELETE /api/v1/intel/feed", s.auth(http.HandlerFunc(s.intelFeedDelete)))
	mux.Handle("GET /api/v1/intel/hits", s.auth(http.HandlerFunc(s.intelHits)))
	mux.Handle("GET /api/v1/intel/dns-hits", s.auth(http.HandlerFunc(s.intelDNSHits)))
	mux.Handle("POST /api/v1/intel/apply", s.auth(http.HandlerFunc(s.intelApply)))
	mux.Handle("GET /api/v1/ebpf/ai-destinations", s.auth(http.HandlerFunc(s.aiDestinations)))
	mux.Handle("POST /api/v1/ebpf/ai-destinations/deny", s.auth(http.HandlerFunc(s.aiDestinationsDeny)))
	mux.Handle("GET /api/v1/ebpf/app-categories", s.auth(http.HandlerFunc(s.appCategories)))
	mux.Handle("GET /api/v1/ebpf/auto-mitigate", s.auth(http.HandlerFunc(s.autoMitigateStatus)))
	mux.Handle("GET /api/v1/compliance", s.auth(http.HandlerFunc(s.complianceReport)))
	mux.Handle("GET /api/v1/ebpf/coverage", s.auth(http.HandlerFunc(s.ebpfCoverage)))
	mux.Handle("GET /api/v1/fleet", s.auth(http.HandlerFunc(s.fleetInventory)))
	mux.Handle("GET /api/v1/fleet/clusters", s.auth(http.HandlerFunc(s.fleetClusters)))
	mux.Handle("GET /api/v1/fleet/tenants", s.auth(http.HandlerFunc(s.fleetTenants)))
	mux.Handle("GET /api/v1/ebpf/tls-fingerprints", s.auth(http.HandlerFunc(s.tlsFingerprints)))
	mux.Handle("GET /api/v1/ebpf/tls-fingerprints/risk", s.auth(http.HandlerFunc(s.tlsFingerprintRisk)))
	mux.Handle("GET /api/v1/ebpf/encrypted-dns", s.auth(http.HandlerFunc(s.encDNS)))
	mux.Handle("GET /api/v1/report/prevention", s.auth(http.HandlerFunc(s.preventionReport)))
	mux.Handle("GET /api/v1/node-resources", s.auth(http.HandlerFunc(s.nodeResources)))
	mux.Handle("GET /api/v1/handoff", s.auth(http.HandlerFunc(s.operatorHandoff)))
	mux.Handle("GET /api/v1/scorecard", s.auth(http.HandlerFunc(s.operatorScorecard)))
	mux.Handle("GET /api/v1/ebpf/reasons", s.auth(http.HandlerFunc(s.dropReasons)))
	mux.Handle("GET /api/v1/talkers", s.auth(http.HandlerFunc(s.topTalkers)))
	mux.Handle("POST /api/v1/watchlist/match", s.auth(http.HandlerFunc(s.watchlistMatch)))
	mux.Handle("GET /api/v1/namespaces/heat", s.auth(http.HandlerFunc(s.namespaceHeat)))
	mux.Handle("GET /api/v1/protocols", s.auth(http.HandlerFunc(s.protocolMix)))
	mux.Handle("GET /api/v1/ebpf/census", s.auth(http.HandlerFunc(s.denyCensus)))
	mux.Handle("GET /api/v1/ebpf/maps", s.auth(http.HandlerFunc(s.ebpfMaps)))
	mux.Handle("GET /api/v1/baselines", s.auth(http.HandlerFunc(s.baselineStatus)))
	mux.Handle("GET /api/v1/ports", s.auth(http.HandlerFunc(s.portHeat)))
	mux.Handle("GET /api/v1/dns/board", s.auth(http.HandlerFunc(s.dnsBoard)))
	mux.Handle("GET /api/v1/lease", s.auth(http.HandlerFunc(s.leaseStatus)))
	mux.Handle("GET /api/v1/incidents", s.auth(http.HandlerFunc(s.incidents)))
	mux.Handle("GET /api/v1/incidents/timeline", s.auth(http.HandlerFunc(s.incidentsTimeline)))
	mux.Handle("GET /api/v1/ai/status", s.auth(http.HandlerFunc(s.aiStatus)))
	mux.Handle("GET /api/v1/ai/brief", s.auth(http.HandlerFunc(s.aiBrief)))
	mux.Handle("GET /api/v1/ai/congestion-brief", s.auth(http.HandlerFunc(s.aiCongestionBrief)))
	mux.Handle("POST /api/v1/ai/ask", s.auth(http.HandlerFunc(s.aiAsk)))
	mux.Handle("POST /api/v1/ai/forget", s.auth(http.HandlerFunc(s.aiForget)))
	mux.Handle("POST /api/v1/ai/draft", s.auth(http.HandlerFunc(s.aiDraft)))
	mux.Handle("GET /api/v1/ai/digest", s.auth(http.HandlerFunc(s.aiDigest)))
	mux.Handle("GET /api/v1/ai/suggestions", s.auth(http.HandlerFunc(s.aiSuggestions)))
	mux.Handle("POST /api/v1/ai/explain", s.auth(http.HandlerFunc(s.aiExplain)))
	mux.Handle("POST /api/v1/ai/agent", s.auth(http.HandlerFunc(s.aiAgent)))
	mux.Handle("POST /api/v1/agents/report", s.agentAuth(http.HandlerFunc(s.agentReport)))
	mux.Handle("POST /api/v1/agents/metrics", s.agentAuth(http.HandlerFunc(s.agentMetricsIngest)))
	mux.Handle("GET /api/v1/metrics/nodes", s.auth(http.HandlerFunc(s.metricsNodes)))
	mux.Handle("GET /api/v1/metrics/contexts", s.auth(http.HandlerFunc(s.metricsContexts)))
	mux.Handle("GET /api/v1/metrics/data", s.auth(http.HandlerFunc(s.metricsQuery)))
	mux.Handle("GET /api/v1/metrics/stream", s.auth(http.HandlerFunc(s.metricsStream)))
	mux.Handle("GET /api/v1/metrics/anomalies", s.auth(http.HandlerFunc(s.metricsAnomalies)))
	mux.Handle("GET /api/v1/metrics/evidence", s.auth(http.HandlerFunc(s.metricsEvidence)))
	mux.Handle("GET /api/v1/metrics/summary", s.auth(http.HandlerFunc(s.metricsSummary)))
	mux.Handle("GET /api/v1/metrics/fleet", s.auth(http.HandlerFunc(s.metricsFleet)))
	mux.Handle("GET /api/v1/metrics/alerts", s.auth(http.HandlerFunc(s.metricsAlerts)))
	mux.Handle("GET /api/v1/metrics/exporters", s.auth(http.HandlerFunc(s.metricsExporters)))
	mux.Handle("POST /api/v1/metrics/alerts/silences", s.auth(http.HandlerFunc(s.metricsAlertSilence)))
	mux.Handle("DELETE /api/v1/metrics/alerts/silences/{id}", s.auth(http.HandlerFunc(s.metricsAlertUnsilence)))
	mux.Handle("POST /api/v1/metrics/alerts/{id}/ack", s.auth(http.HandlerFunc(s.metricsAlertAck)))
	mux.HandleFunc("/", s.serveWeb)
	return requestLog(s.log, s.metricsData, securityHeaders(mux))
}

func (s *Server) cilium(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.ciliumEnabled {
			errorJSON(w, http.StatusConflict, "Cilium integration is disabled; enable NETRA_CILIUM_ENABLED or Helm cilium.enabled")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authRequired() {
			next.ServeHTTP(w, r)
			return
		}
		p, res := s.authenticate(r)
		switch res {
		case authOK:
		case authForbidden:
			s.metricsData.authFailures.Add(1)
			errorJSON(w, http.StatusForbidden, "token is valid but carries no Netra role")
			return
		case authUnavailable:
			errorJSON(w, http.StatusServiceUnavailable, "identity provider keys unavailable; retry")
			return
		default:
			s.metricsData.authFailures.Add(1)
			errorJSON(w, 401, "invalid API token")
			return
		}
		if need := requiredRole(r); !p.role.AtLeast(need) {
			s.metricsData.rbacDenied.Add(1)
			if s.log != nil {
				s.log.Warn("request denied by role", "actor", p.name, "kind", p.kind, "role", p.role.String(), "need", need.String(), "route", r.Method+" "+r.URL.Path)
			}
			errorJSON(w, http.StatusForbidden, "role "+p.role.String()+" cannot perform this action; "+need.String()+" required")
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

func (s *Server) agentAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.agentKey != "" && !secureEq(r.Header.Get("X-Netra-Agent-Key"), s.agentKey) {
			s.metricsData.authFailures.Add(1)
			errorJSON(w, 401, "invalid agent key")
			return
		}
		if !mtls.Allows(s.agentMTLS, r) {
			s.metricsData.mtlsRejected.Add(1)
			errorJSON(w, 401, "a verified agent client certificate is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) authOrAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authRequired() && s.agentKey == "" {
			next.ServeHTTP(w, r)
			return
		}
		p, res := s.authenticate(r)
		apiOK := res == authOK && p.role.AtLeast(oidcauth.RoleViewer)
		agentOK := s.agentKey != "" && secureEq(r.Header.Get("X-Netra-Agent-Key"), s.agentKey)
		if agentOK && !apiOK && !mtls.Allows(s.agentMTLS, r) {
			// A correct agent key without the required certificate is not an agent.
			s.metricsData.mtlsRejected.Add(1)
			agentOK = false
		}
		if !apiOK && !agentOK {
			s.metricsData.authFailures.Add(1)
			errorJSON(w, 401, "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func secureEq(got, want string) bool {
	return len(got) == len(want) && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func bearer(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(v), "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	if t := strings.TrimSpace(r.URL.Query().Get("token")); t != "" {
		return t
	}
	return ""
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	hs, err := s.hubble.Status(ctx)
	statuses := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
	stale := 0
	for _, a := range statuses {
		if a.Stale {
			stale++
		}
	}
	baseline := s.store.Baseline()
	rateBaseline := s.store.RateBaseline()
	rateWindow := s.store.RateWindow(5*time.Minute, time.Now())
	out := map[string]any{"version": "0.29.0", "datapath": "standalone-ebpf", "ciliumRequired": false, "ciliumEnabled": s.ciliumEnabled, "consoleEnabled": s.consoleEnabled, "fastPath": s.store.Config(), "agents": len(statuses), "staleAgents": stale, "requirePreflight": s.requirePreflight, "persistentState": s.store.Persistent(), "haEnabled": strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_HA_ENABLED")), "true"), "controllerIdentity": strings.TrimSpace(os.Getenv("NETRA_POD_NAME")), "baselineEntries": len(baseline.Entries), "rateBaselineEntries": len(rateBaseline.Entries), "rateWindowWarming": rateWindow.Warming}
	if !baseline.CapturedAt.IsZero() {
		out["baselineCapturedAt"] = baseline.CapturedAt
	}
	if !rateBaseline.CapturedAt.IsZero() {
		out["rateBaselineCapturedAt"] = rateBaseline.CapturedAt
	}
	if err != nil {
		out["hubbleError"] = err.Error()
	} else {
		out["hubble"] = hs
	}
	writeJSON(w, 200, out)
}
func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = "default"
	}
	b, err := s.kube.ListPolicies(r.Context(), ns)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	writeRawJSON(w, 200, b)
}
func (s *Server) buildPolicy(w http.ResponseWriter, r *http.Request) {
	var req models.BuildPolicyRequest
	if err := decodeJSON(r, &req, 1<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	b, err := policy.Build(req)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	writeRawJSON(w, 200, b)
}
func (s *Server) planPolicy(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	ns, name, err := kube.ExtractIdentity(b)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	current, found, err := s.kube.GetPolicy(r.Context(), ns, name)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	plan, err := policy.AnalyzeChange(current, b)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	plan.Exists = found
	_, err = s.kube.ApplyPolicy(r.Context(), ns, name, b, true)
	dryRun := map[string]any{"passed": err == nil}
	var receipt any
	if err != nil {
		dryRun["error"] = err.Error()
		if plan.Risk == "low" || plan.Risk == "medium" {
			plan.Risk = "high"
		}
		plan.Warnings = append(plan.Warnings, "Kubernetes server-side dry-run failed; do not apply until the error is resolved")
	} else {
		rcpt, issueErr := s.store.IssuePreflight(b, plan.Risk, actor(r), 5*time.Minute)
		if issueErr != nil {
			if errors.Is(issueErr, store.ErrPersistence) {
				s.metricsData.statePersistErrors.Add(1)
				errorJSON(w, http.StatusInsufficientStorage, "could not persist preflight receipt: "+issueErr.Error())
			} else {
				errorJSON(w, 500, "could not issue preflight receipt")
			}
			return
		}
		receipt = rcpt
	}
	s.metricsData.policyPlans.Add(1)
	writeJSON(w, 200, map[string]any{"plan": plan, "dryRun": dryRun, "receipt": receipt})
}

// simulatePolicy is pure read/analysis — it never calls kube.ApplyPolicy and
// needs no preflight receipt, since nothing is applied. It evaluates the
// candidate against internal insights.Dependencies()/agent-reported
// workload labels only, so — unlike plan/apply — it does not require Cilium
// integration to be enabled; a candidate manifest can be simulated as
// evidence for review whether or not Netra can apply it here.
func (s *Server) simulatePolicy(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	graph, err := s.dependencyGraph(r, 5000)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	sim, err := insights.Simulate(b, graph, s.store.AgentStatuses(time.Now(), s.agentStaleAfter))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, sim)
}

func (s *Server) applyPolicy(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	ns, name, err := kube.ExtractIdentity(b)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	dry := r.URL.Query().Get("dryRun") == "true"
	if !dry && s.requirePreflight {
		token := strings.TrimSpace(r.Header.Get("X-Netra-Plan-Token"))
		if token == "" {
			s.metricsData.preflightRejects.Add(1)
			errorJSON(w, http.StatusPreconditionRequired, "a fresh preflight receipt is required; run /api/v1/policies/plan first")
			return
		}
		risk, ok, consumeErr := s.store.ConsumePreflight(token, b)
		if consumeErr != nil {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, "could not persist preflight consumption: "+consumeErr.Error())
			return
		}
		if !ok {
			s.metricsData.preflightRejects.Add(1)
			errorJSON(w, http.StatusPreconditionFailed, "preflight receipt is expired, already used, or does not match this exact policy body")
			return
		}
		if risk == "high" || risk == "critical" {
			if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Netra-Confirm-Risk")), risk) {
				s.metricsData.preflightRejects.Add(1)
				errorJSON(w, 409, "preflight risk is "+risk+"; repeat preflight and apply with X-Netra-Confirm-Risk: "+risk)
				return
			}
		}
	}
	var current []byte
	var found bool
	if !dry {
		current, found, err = s.kube.GetPolicy(r.Context(), ns, name)
		if err != nil {
			errorJSON(w, 502, err.Error())
			return
		}
	}
	out, err := s.kube.ApplyPolicy(r.Context(), ns, name, b, dry)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	if !dry {
		who := actor(r)
		if found {
			if snap, snapErr := kube.PreparePolicyForApply(current); snapErr == nil {
				_, stateErr := s.store.RecordPolicyRevision(ns, name, "checkpoint", who, snap)
				s.stateWarning(w, stateErr)
			}
		}
		if snap, snapErr := kube.PreparePolicyForApply(out); snapErr == nil {
			_, stateErr := s.store.RecordPolicyRevision(ns, name, "apply", who, snap)
			s.stateWarning(w, stateErr)
		} else if snap, snapErr := kube.PreparePolicyForApply(b); snapErr == nil {
			_, stateErr := s.store.RecordPolicyRevision(ns, name, "apply", who, snap)
			s.stateWarning(w, stateErr)
		}
		s.metricsData.policyApplies.Add(1)
		s.stateWarning(w, s.store.AddAudit(models.AuditEvent{Actor: who, Action: "policy.apply", Target: ns + "/" + name}))
	}
	writeRawJSON(w, 200, out)
}

var errGitOpsDisabled = errors.New("GitOps is not enabled (set NETRA_GITOPS_DIR)")

func (s *Server) gitopsStatus(w http.ResponseWriter, _ *http.Request) {
	if s.gitops == nil {
		errorJSON(w, http.StatusConflict, errGitOpsDisabled.Error())
		return
	}
	writeJSON(w, 200, s.gitops.Status())
}

// gitopsResync is the explicit human override for a manifest Reconcile's
// unattended pass declined to auto-apply (drift, or high/critical risk) —
// same X-Netra-Confirm-Risk semantics as any other high-blast-radius
// mutation in this codebase.
func (s *Server) gitopsResync(w http.ResponseWriter, r *http.Request) {
	if s.gitops == nil {
		errorJSON(w, http.StatusConflict, errGitOpsDisabled.Error())
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	confirmedRisk := strings.TrimSpace(r.Header.Get("X-Netra-Confirm-Risk"))
	plan, err := s.gitops.Resync(r.Context(), b, confirmedRisk)
	if err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, plan)
}

func (s *Server) policyHistory(w http.ResponseWriter, r *http.Request) {
	ns := strings.TrimSpace(r.URL.Query().Get("namespace"))
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	writeJSON(w, 200, map[string]any{"items": s.store.PolicyHistory(ns, name, limit)})
}

func (s *Server) exportPolicyHistory(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Disposition", `attachment; filename="netra-policy-history.json"`)
	writeJSON(w, 200, s.store.ExportPolicyArchive())
}

func (s *Server) importPolicyHistory(w http.ResponseWriter, r *http.Request) {
	var archive models.PolicyArchive
	if err := decodeJSON(r, &archive, 16<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
	if mode == "replace" && !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Netra-Confirm-History-Replace")), "replace") {
		errorJSON(w, 409, "replacing history requires X-Netra-Confirm-History-Replace: replace")
		return
	}
	for i := range archive.Revisions {
		snap, err := kube.PreparePolicyForApply(archive.Revisions[i].Manifest)
		if err != nil {
			errorJSON(w, 400, fmt.Sprintf("revision %d is not an applyable Cilium policy snapshot: %v", i, err))
			return
		}
		ns, name, err := kube.ExtractIdentity(snap)
		if err != nil || ns != archive.Revisions[i].Namespace || name != archive.Revisions[i].Name {
			errorJSON(w, 400, fmt.Sprintf("revision %d manifest identity does not match archive metadata", i))
			return
		}
		archive.Revisions[i].Manifest = snap
	}
	count, err := s.store.ImportPolicyArchive(archive, mode, actor(r))
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
		} else {
			errorJSON(w, 400, err.Error())
		}
		return
	}
	writeJSON(w, 200, map[string]any{"imported": count, "mode": func() string {
		if mode == "" {
			return "merge"
		}
		return mode
	}()})
}

func (s *Server) stateWarning(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	s.metricsData.statePersistErrors.Add(1)
	s.log.Error("durable state write failed after cluster mutation", "error", err)
	w.Header().Set("X-Netra-State-Warning", "persistence-failed")
	w.Header().Add("Warning", `199 Netra "cluster mutation succeeded but durable local history write failed"`)
}

func (s *Server) rollbackPolicy(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("namespace")
	name := r.PathValue("name")
	id, err := strconv.ParseUint(r.PathValue("revision"), 10, 64)
	if err != nil || id == 0 {
		errorJSON(w, 400, "valid revision id required")
		return
	}
	rev, ok := s.store.PolicyRevision(ns, name, id)
	if !ok {
		errorJSON(w, 404, "policy revision not found")
		return
	}
	current, found, err := s.kube.GetPolicy(r.Context(), ns, name)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	plan, err := policy.AnalyzeChange(current, rev.Manifest)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	plan.Exists = found
	_, dryErr := s.kube.ApplyPolicy(r.Context(), ns, name, rev.Manifest, true)
	dryRun := map[string]any{"passed": dryErr == nil}
	if dryErr != nil {
		dryRun["error"] = dryErr.Error()
		plan.Warnings = append(plan.Warnings, "rollback Kubernetes server-side dry-run failed")
		elevateRiskForAPI(&plan, "high")
	}
	if r.URL.Query().Get("dryRun") == "true" {
		writeJSON(w, 200, map[string]any{"revision": rev, "plan": plan, "dryRun": dryRun})
		return
	}
	if dryErr != nil {
		errorJSON(w, 409, "rollback dry-run failed; inspect with ?dryRun=true")
		return
	}
	if plan.Risk == "high" || plan.Risk == "critical" {
		if !strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("confirmRisk")), plan.Risk) {
			errorJSON(w, 409, "rollback risk is "+plan.Risk+"; repeat with confirmRisk="+plan.Risk)
			return
		}
	}
	who := actor(r)
	if found {
		if snap, snapErr := kube.PreparePolicyForApply(current); snapErr == nil {
			_, stateErr := s.store.RecordPolicyRevision(ns, name, "rollback-checkpoint", who, snap)
			s.stateWarning(w, stateErr)
		}
	}
	out, err := s.kube.ApplyPolicy(r.Context(), ns, name, rev.Manifest, false)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	if snap, snapErr := kube.PreparePolicyForApply(out); snapErr == nil {
		_, stateErr := s.store.RecordPolicyRevision(ns, name, "rollback", who, snap)
		s.stateWarning(w, stateErr)
	} else {
		_, stateErr := s.store.RecordPolicyRevision(ns, name, "rollback", who, rev.Manifest)
		s.stateWarning(w, stateErr)
	}
	s.metricsData.policyRollbacks.Add(1)
	s.stateWarning(w, s.store.AddAudit(models.AuditEvent{Actor: who, Action: "policy.rollback", Target: ns + "/" + name, Details: map[string]any{"revision": id, "risk": plan.Risk}}))
	writeRawJSON(w, 200, out)
}

func elevateRiskForAPI(plan *policy.ChangePlan, risk string) {
	rank := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	if rank[risk] > rank[plan.Risk] {
		plan.Risk = risk
	}
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	ns, name := r.PathValue("namespace"), r.PathValue("name")
	current, found, err := s.kube.GetPolicy(r.Context(), ns, name)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	if !found {
		errorJSON(w, 404, "policy not found")
		return
	}
	if err := s.kube.DeletePolicy(r.Context(), ns, name); err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	who := actor(r)
	if snap, snapErr := kube.PreparePolicyForApply(current); snapErr == nil {
		_, stateErr := s.store.RecordPolicyRevision(ns, name, "delete-checkpoint", who, snap)
		s.stateWarning(w, stateErr)
	}
	s.metricsData.policyDeletes.Add(1)
	s.stateWarning(w, s.store.AddAudit(models.AuditEvent{Actor: who, Action: "policy.delete", Target: ns + "/" + name}))
	writeJSON(w, 200, map[string]any{"deleted": true})
}

func (s *Server) flowSummary(w http.ResponseWriter, r *http.Request) {
	n := uint64(500)
	if x, err := strconv.ParseUint(r.URL.Query().Get("number"), 10, 64); err == nil && x > 0 && x <= 5000 {
		n = x
	}
	filter := hubble.Filter{
		Verdict:     r.URL.Query().Get("verdict"),
		Namespace:   r.URL.Query().Get("namespace"),
		Pod:         r.URL.Query().Get("pod"),
		Direction:   r.URL.Query().Get("direction"),
		Protocol:    r.URL.Query().Get("protocol"),
		Destination: r.URL.Query().Get("destination"),
	}
	if filter.Verdict != "" && !oneOfFold(filter.Verdict, "FORWARDED", "DROPPED", "ERROR", "AUDIT", "REDIRECTED", "TRACED", "TRANSLATED") {
		errorJSON(w, 400, "unsupported verdict")
		return
	}
	if filter.Direction != "" && !oneOfFold(filter.Direction, "EGRESS", "INGRESS") {
		errorJSON(w, 400, "direction must be EGRESS or INGRESS")
		return
	}
	if filter.Destination != "" {
		if _, err := netip.ParseAddr(filter.Destination); err != nil {
			if _, err := netip.ParsePrefix(filter.Destination); err != nil {
				errorJSON(w, 400, "destination must be an IP address or CIDR")
				return
			}
		}
	}
	collector := flowstats.New()
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	err := s.hubble.Stream(ctx, n, false, filter, func(b []byte) error {
		if hubble.MatchFlowJSON(b, filter) {
			collector.Add(b)
		}
		return nil
	})
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		errorJSON(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, collector.Summary(10))
}

func (s *Server) streamFlows(w http.ResponseWriter, r *http.Request) {
	f, ok := w.(http.Flusher)
	if !ok {
		errorJSON(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	n := uint64(100)
	if x, err := strconv.ParseUint(r.URL.Query().Get("number"), 10, 64); err == nil && x <= 5000 {
		n = x
	}
	filter := hubble.Filter{
		Verdict:     r.URL.Query().Get("verdict"),
		Namespace:   r.URL.Query().Get("namespace"),
		Pod:         r.URL.Query().Get("pod"),
		Direction:   r.URL.Query().Get("direction"),
		Protocol:    r.URL.Query().Get("protocol"),
		Destination: r.URL.Query().Get("destination"),
	}
	if filter.Verdict != "" && !oneOfFold(filter.Verdict, "FORWARDED", "DROPPED", "ERROR", "AUDIT", "REDIRECTED", "TRACED", "TRANSLATED") {
		errorJSON(w, 400, "unsupported verdict")
		return
	}
	if filter.Direction != "" && !oneOfFold(filter.Direction, "EGRESS", "INGRESS") {
		errorJSON(w, 400, "direction must be EGRESS or INGRESS")
		return
	}
	if filter.Destination != "" {
		if _, err := netip.ParseAddr(filter.Destination); err != nil {
			if _, err := netip.ParsePrefix(filter.Destination); err != nil {
				errorJSON(w, 400, "destination must be an IP address or CIDR")
				return
			}
		}
	}
	fmt.Fprintf(w, "event: ready\ndata: {\"source\":\"hubble-relay\"}\n\n")
	f.Flush()
	err := s.hubble.Stream(r.Context(), n, true, filter, func(b []byte) error {
		if !hubble.MatchFlowJSON(b, filter) {
			return nil
		}
		if _, err := fmt.Fprintf(w, "event: flow\ndata: %s\n\n", b); err != nil {
			return err
		}
		f.Flush()
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		s.log.Warn("Hubble stream ended", "error", err)
	}
}

// ebpfDropExplain is the unified "explain a drop" endpoint: standalone
// eBPF Drop Detective findings are always computed (primary, Cilium-
// independent, per docs/standalone-ebpf.md); Hubble flows are appended as
// an additional Source when Hubble is configured, and are skipped rather
// than treated as an error when it isn't (the common case) or is
// unreachable. Served at both GET /api/v1/ebpf/explain and (for backward
// compatibility of the URL, not the response shape — see docs/drop-explain.md)
// GET /api/v1/drops/explain.
func (s *Server) ebpfDropExplain(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 100 {
		limit = n
	}
	agentLimit := 50
	if v := r.URL.Query().Get("agentLimit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			agentLimit = n
		}
	}
	namespace, pod := r.URL.Query().Get("namespace"), r.URL.Query().Get("pod")
	hubbleFn := func() ([]detective.UnifiedFinding, error) {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		raw := make([]map[string]any, 0, limit)
		filter := hubble.Filter{Verdict: "DROPPED", Namespace: namespace, Pod: pod}
		err := s.hubble.Stream(ctx, 500, false, filter, func(b []byte) error {
			if !hubble.MatchFlowJSON(b, filter) {
				return nil
			}
			x := hubble.Explain(b)
			enrichExplanation(x)
			raw = append(raw, x)
			if len(raw) >= limit {
				return io.EOF
			}
			return nil
		})
		if err != nil && err != io.EOF {
			return nil, err
		}
		return detective.HubbleFindingsFromExplain(raw), nil
	}
	out, err := detective.BuildUnified(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), s.store.Config(), agentLimit, hubbleFn)
	if err != nil {
		s.log.Debug("hubble explain unavailable; returning standalone findings only", "error", err)
	}
	writeJSON(w, 200, out)
}
func enrichExplanation(x map[string]any) {
	reason := strings.ToUpper(fmt.Sprint(x["dropReason"]))
	suggestions := []string{}
	summary := "Hubble reported a dropped flow."
	if strings.Contains(reason, "POLICY") || strings.Contains(reason, "DENIED") {
		summary = "Cilium policy enforcement denied this flow."
		suggestions = append(suggestions, "Check the selected endpoint's egress CiliumNetworkPolicy rules.", "Verify destination CIDR/FQDN/entity and L4 port are explicitly allowed.")
	}
	if strings.Contains(reason, "CT") {
		suggestions = append(suggestions, "Inspect Cilium conntrack pressure and connection state on the emitting node.")
	}
	if strings.Contains(reason, "NO SERVICE") || strings.Contains(reason, "SERVICE") {
		suggestions = append(suggestions, "Verify Service backends and endpoint readiness.")
	}
	if len(suggestions) == 0 {
		suggestions = append(suggestions, "Inspect the Hubble drop reason, observation point, identities, and matching Cilium policies.")
	}
	x["summary"] = summary
	x["suggestions"] = suggestions
}
func (s *Server) ebpfConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.Config()
	node := strings.TrimSpace(r.URL.Query().Get("node"))
	if node != "" {
		cfg.DesiredCapture = s.store.Capture(node)
		cfg.NodeIsolation = s.store.NodeIsolation(node)
	}
	if node != "" && s.kube != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		items, err := s.kube.ListWorkloads(ctx, node)
		if err != nil {
			// Fall back to the last successful inventory for this node
			// rather than letting cfg.Workloads go out empty: an agent
			// re-resolving its cgroups against an empty pod list doesn't
			// treat that as "unknown," it treats it as "zero workloads on
			// this node" (internal/workload.Resolve's documented fail-open
			// behavior), which blanks out every workload's
			// Namespace/Pod/WorkloadName until the next successful call.
			// See workloadInventoryCache's doc comment.
			if cached, ok := s.workloadInventory.get(node); ok {
				s.log.Warn("load node workload inventory: using last-known-good", "node", node, "error", err, "cachedWorkloads", len(cached))
				cfg.Workloads = cached
			} else {
				s.log.Warn("load node workload inventory", "node", node, "error", err)
			}
		} else {
			cfg.Workloads = items
			s.workloadInventory.set(node, items)
		}
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfWorkloads(w http.ResponseWriter, r *http.Request) {
	if s.kube == nil {
		errorJSON(w, http.StatusServiceUnavailable, "Kubernetes client unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	items, err := s.kube.ListWorkloads(ctx, strings.TrimSpace(r.URL.Query().Get("node")))
	if err != nil {
		errorJSON(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) ebpfScope(w http.ResponseWriter, r *http.Request) {
	var x struct {
		Mode   string                     `json:"mode"`
		Scopes []models.EBPFWorkloadScope `json:"scopes"`
	}
	if err := decodeJSON(r, &x, 1<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	x.Mode = strings.ToLower(strings.TrimSpace(x.Mode))
	if x.Mode == "" {
		x.Mode = "all"
	}
	if x.Mode != "all" && x.Mode != "selected" {
		errorJSON(w, 400, "scope mode must be all or selected")
		return
	}
	for i := range x.Scopes {
		sc := &x.Scopes[i]
		sc.Namespace, sc.Pod = strings.TrimSpace(sc.Namespace), strings.TrimSpace(sc.Pod)
		sc.WorkloadKind, sc.WorkloadName = strings.TrimSpace(sc.WorkloadKind), strings.TrimSpace(sc.WorkloadName)
		clean := map[string]string{}
		for k, v := range sc.Labels {
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if k == "" {
				errorJSON(w, 400, "scope label key cannot be empty")
				return
			}
			clean[k] = v
		}
		sc.Labels = clean
		if sc.CgroupID == 0 && sc.Namespace == "" && sc.Pod == "" && sc.WorkloadKind == "" && sc.WorkloadName == "" && len(sc.Labels) == 0 {
			errorJSON(w, 400, "empty workload scope is not allowed")
			return
		}
	}
	if x.Mode == "selected" && len(x.Scopes) == 0 {
		errorJSON(w, 400, "selected scope mode requires at least one workload scope")
		return
	}
	cfg, err := s.store.SetWorkloadScopes(x.Mode, x.Scopes, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist workload scope: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfScopePreview(w http.ResponseWriter, r *http.Request) {
	var x struct {
		Scopes []models.EBPFWorkloadScope `json:"scopes"`
	}
	if err := decodeJSON(r, &x, 1<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if len(x.Scopes) == 0 {
		errorJSON(w, 400, "at least one workload scope is required")
		return
	}
	if s.kube == nil {
		errorJSON(w, http.StatusServiceUnavailable, "Kubernetes client unavailable")
		return
	}
	items, err := s.kube.ListWorkloads(r.Context(), "")
	if err != nil {
		errorJSON(w, http.StatusBadGateway, err.Error())
		return
	}
	matched := make([]models.WorkloadIdentity, 0)
	for _, pod := range items {
		for _, scope := range x.Scopes {
			if workload.Match(scope, pod) {
				matched = append(matched, pod)
				break
			}
		}
	}
	writeJSON(w, 200, map[string]any{"matched": matched, "count": len(matched), "totalPods": len(items)})
}

func (s *Server) ebpfTopology(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 1000 {
		limit = n
	}
	writeJSON(w, 200, map[string]any{"items": observability.Topology(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit)})
}

func (s *Server) ebpfMode(w http.ResponseWriter, r *http.Request) {
	var x struct {
		Mode string `json:"mode"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	x.Mode = strings.ToLower(x.Mode)
	if x.Mode != "observe" && x.Mode != "enforce" {
		errorJSON(w, 400, "mode must be observe or enforce")
		return
	}
	lease := time.Duration(0)
	if x.Mode == "enforce" {
		lease = 15 * time.Minute
		if raw := r.URL.Query().Get("lease"); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil || d < time.Minute || d > 24*time.Hour {
				errorJSON(w, 400, "lease must be a duration between 1m and 24h")
				return
			}
			lease = d
		}
	}
	cfg, err := s.store.SetMode(x.Mode, lease, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist fast-path state: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfDenyAdd(w http.ResponseWriter, r *http.Request) {
	var x struct {
		IP        string `json:"ip"`
		Direction string `json:"direction"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	a, err := netip.ParseAddr(strings.TrimSpace(x.IP))
	if err != nil {
		errorJSON(w, 400, "a valid IPv4 or IPv6 address is required")
		return
	}
	dir := strings.ToLower(strings.TrimSpace(x.Direction))
	if dir == "" {
		dir = "egress"
	}
	if dir != "egress" && dir != "ingress" && dir != "both" {
		errorJSON(w, 400, "direction must be egress, ingress, or both")
		return
	}
	var cfg models.EBPFFastPathConfig
	act := actor(r)
	if dir == "egress" || dir == "both" {
		if a.Is4() {
			cfg, err = s.store.AddBlocked(a.String(), act)
		} else {
			cfg, err = s.store.AddBlockedIPv6(a.String(), act)
		}
		if err != nil {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, "could not persist deny map: "+err.Error())
			return
		}
	}
	if dir == "ingress" || dir == "both" {
		if a.Is4() {
			cfg, err = s.store.AddBlockedIngress(a.String(), act)
		} else {
			cfg, err = s.store.AddBlockedIngressIPv6(a.String(), act)
		}
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist deny map: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfAllowAdd(w http.ResponseWriter, r *http.Request) {
	var x struct {
		IP string `json:"ip"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	a, err := netip.ParseAddr(strings.TrimSpace(x.IP))
	if err != nil {
		errorJSON(w, 400, "a valid IPv4 or IPv6 address is required")
		return
	}
	var cfg models.EBPFFastPathConfig
	if a.Is4() {
		cfg, err = s.store.AddAllowed(a.String(), actor(r))
	} else {
		cfg, err = s.store.AddAllowedIPv6(a.String(), actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist allow map: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfAllowDelete(w http.ResponseWriter, r *http.Request) {
	a, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		errorJSON(w, 400, "valid IPv4 or IPv6 required")
		return
	}
	var cfg models.EBPFFastPathConfig
	if a.Is4() {
		cfg, err = s.store.DelAllowed(a.String(), actor(r))
	} else {
		cfg, err = s.store.DelAllowedIPv6(a.String(), actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist allow map: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfDenyDelete(w http.ResponseWriter, r *http.Request) {
	a, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		errorJSON(w, 400, "valid IPv4 or IPv6 required")
		return
	}
	act := actor(r)
	// An exact-IP deny may exist in the egress list, the ingress list, or
	// both (added via "both" direction) — clear whichever this address
	// is actually in, so callers can delete by IP alone without needing
	// to know which direction it was added under.
	var cfg models.EBPFFastPathConfig
	if a.Is4() {
		cfg, err = s.store.DelBlocked(a.String(), act)
		if err != nil {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, "could not persist deny map: "+err.Error())
			return
		}
		cfg, err = s.store.DelBlockedIngress(a.String(), act)
	} else {
		cfg, err = s.store.DelBlockedIPv6(a.String(), act)
		if err != nil {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, "could not persist deny map: "+err.Error())
			return
		}
		cfg, err = s.store.DelBlockedIngressIPv6(a.String(), act)
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist deny map: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func normalizeDirection(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		v = "egress"
	}
	return v, v == "egress" || v == "ingress" || v == "both"
}
func (s *Server) ebpfCIDRAdd(w http.ResponseWriter, r *http.Request)    { s.ebpfCIDRMutate(w, r, false) }
func (s *Server) ebpfCIDRDelete(w http.ResponseWriter, r *http.Request) { s.ebpfCIDRMutate(w, r, true) }
func (s *Server) ebpfCIDRMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x models.EBPFCIDRRule
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(x.CIDR))
	if err != nil {
		errorJSON(w, 400, "valid IPv4 or IPv6 CIDR required")
		return
	}
	x.CIDR = p.Masked().String()
	var ok bool
	x.Direction, ok = normalizeDirection(x.Direction)
	if !ok {
		errorJSON(w, 400, "direction must be ingress, egress, or both")
		return
	}
	var cfg models.EBPFFastPathConfig
	if del {
		cfg, err = s.store.DelCIDR(x, actor(r))
	} else {
		cfg, err = s.store.AddCIDR(x, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist CIDR rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfSynDropAdd(w http.ResponseWriter, r *http.Request) {
	s.ebpfSynDropMutate(w, r, false)
}
func (s *Server) ebpfSynDropDelete(w http.ResponseWriter, r *http.Request) {
	s.ebpfSynDropMutate(w, r, true)
}
func (s *Server) ebpfSynDropMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x models.EBPFSynDropEntry
	if err := decodeJSON(r, &x, 1<<12); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	a, err := netip.ParseAddr(strings.TrimSpace(x.Address))
	if err != nil {
		errorJSON(w, 400, "syn-drop requires an exact IPv4 or IPv6 address")
		return
	}
	x.Address = a.String()
	x.Direction = strings.ToLower(strings.TrimSpace(x.Direction))
	if x.Direction != "egress" && x.Direction != "ingress" {
		errorJSON(w, 400, "direction must be egress or ingress (not both — the kernel maps are inherently per-direction)")
		return
	}
	var cfg models.EBPFFastPathConfig
	if del {
		cfg, err = s.store.DelSynDrop(x, actor(r))
	} else {
		cfg, err = s.store.AddSynDrop(x, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist syn-drop entry: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfSynDropCIDRAdd(w http.ResponseWriter, r *http.Request) {
	s.ebpfSynDropCIDRMutate(w, r, false)
}
func (s *Server) ebpfSynDropCIDRDelete(w http.ResponseWriter, r *http.Request) {
	s.ebpfSynDropCIDRMutate(w, r, true)
}
func (s *Server) ebpfSynDropCIDRMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x models.EBPFSynDropCIDR
	if err := decodeJSON(r, &x, 1<<12); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(x.CIDR))
	if err != nil {
		errorJSON(w, 400, "syn-drop-cidr requires a valid IPv4 or IPv6 CIDR")
		return
	}
	x.CIDR = p.Masked().String()
	x.Direction = strings.ToLower(strings.TrimSpace(x.Direction))
	if x.Direction != "egress" && x.Direction != "ingress" {
		errorJSON(w, 400, "direction must be egress or ingress (not both — the kernel maps are inherently per-direction)")
		return
	}
	var cfg models.EBPFFastPathConfig
	if del {
		cfg, err = s.store.DelSynDropCIDR(x, actor(r))
	} else {
		cfg, err = s.store.AddSynDropCIDR(x, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist syn-drop-cidr entry: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfAllowCIDRAdd(w http.ResponseWriter, r *http.Request) {
	s.ebpfAllowCIDRMutate(w, r, false)
}
func (s *Server) ebpfAllowCIDRDelete(w http.ResponseWriter, r *http.Request) {
	s.ebpfAllowCIDRMutate(w, r, true)
}
func (s *Server) ebpfAllowCIDRMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x models.EBPFCIDRRule
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(x.CIDR))
	if err != nil {
		errorJSON(w, 400, "valid IPv4 or IPv6 CIDR required")
		return
	}
	x.CIDR = p.Masked().String()
	var ok bool
	x.Direction, ok = normalizeDirection(x.Direction)
	if !ok {
		errorJSON(w, 400, "direction must be ingress, egress, or both")
		return
	}
	var cfg models.EBPFFastPathConfig
	if del {
		cfg, err = s.store.DelAllowedCIDR(x, actor(r))
	} else {
		cfg, err = s.store.AddAllowedCIDR(x, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist allow CIDR: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func normalizeProtocol(v string) (string, bool) {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		v = "ANY"
	}
	return v, v == "TCP" || v == "UDP" || v == "ANY"
}
func (s *Server) ebpfPortAdd(w http.ResponseWriter, r *http.Request)    { s.ebpfPortMutate(w, r, false) }
func (s *Server) ebpfPortDelete(w http.ResponseWriter, r *http.Request) { s.ebpfPortMutate(w, r, true) }
func (s *Server) ebpfPortMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x models.EBPFPortRule
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if x.Port == 0 {
		errorJSON(w, 400, "port must be 1-65535")
		return
	}
	var ok bool
	x.Protocol, ok = normalizeProtocol(x.Protocol)
	if !ok {
		errorJSON(w, 400, "protocol must be TCP, UDP, or ANY")
		return
	}
	x.Direction, ok = normalizeDirection(x.Direction)
	if !ok {
		errorJSON(w, 400, "direction must be ingress, egress, or both")
		return
	}
	var cfg models.EBPFFastPathConfig
	var err error
	if del {
		cfg, err = s.store.DelPortRule(x, actor(r))
	} else {
		cfg, err = s.store.AddPortRule(x, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist port rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfAllowPortAdd(w http.ResponseWriter, r *http.Request) {
	s.ebpfAllowPortMutate(w, r, false)
}
func (s *Server) ebpfAllowPortDelete(w http.ResponseWriter, r *http.Request) {
	s.ebpfAllowPortMutate(w, r, true)
}
func (s *Server) ebpfAllowPortMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x models.EBPFPortRule
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if x.Port == 0 {
		errorJSON(w, 400, "port must be 1-65535")
		return
	}
	var ok bool
	x.Protocol, ok = normalizeProtocol(x.Protocol)
	if !ok {
		errorJSON(w, 400, "protocol must be TCP, UDP, or ANY")
		return
	}
	x.Direction, ok = normalizeDirection(x.Direction)
	if !ok {
		errorJSON(w, 400, "direction must be ingress, egress, or both")
		return
	}
	var cfg models.EBPFFastPathConfig
	var err error
	if del {
		cfg, err = s.store.DelAllowedPort(x, actor(r))
	} else {
		cfg, err = s.store.AddAllowedPort(x, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist allow-port rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfUIDAdd(w http.ResponseWriter, r *http.Request) {
	var x struct {
		UID uint32 `json:"uid"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	cfg, err := s.store.AddUID(x.UID, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist UID rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfUIDDelete(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.ParseUint(r.PathValue("uid"), 10, 32)
	if err != nil {
		errorJSON(w, 400, "valid UID required")
		return
	}
	cfg, err := s.store.DelUID(uint32(n), actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist UID rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfAllowUIDAdd(w http.ResponseWriter, r *http.Request) {
	var x struct {
		UID uint32 `json:"uid"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	cfg, err := s.store.AddAllowedUID(x.UID, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist allow-uid: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfAllowUIDDelete(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.ParseUint(r.PathValue("uid"), 10, 32)
	if err != nil {
		errorJSON(w, 400, "valid UID required")
		return
	}
	cfg, err := s.store.DelAllowedUID(uint32(n), actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist allow-uid: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func normalizeDNSName(v string) (string, error) {
	v = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
	if v == "" || len(v) > 95 {
		return "", fmt.Errorf("DNS name must be 1-95 bytes")
	}
	for _, label := range strings.Split(v, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("invalid DNS name")
		}
		for i, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') || (r == '-' && (i == 0 || i == len(label)-1)) {
				return "", fmt.Errorf("invalid DNS name")
			}
		}
	}
	return v, nil
}
func (s *Server) ebpfDNSAdd(w http.ResponseWriter, r *http.Request)    { s.ebpfDNSMutate(w, r, false) }
func (s *Server) ebpfDNSDelete(w http.ResponseWriter, r *http.Request) { s.ebpfDNSMutate(w, r, true) }
func (s *Server) ebpfDNSMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	name, err := normalizeDNSName(x.Name)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	var cfg models.EBPFFastPathConfig
	if del {
		cfg, err = s.store.DelDNS(name, actor(r))
	} else {
		cfg, err = s.store.AddDNS(name, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist DNS rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func normalizeProcessName(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || len([]byte(v)) > 15 {
		return "", fmt.Errorf("process name must be 1-15 bytes (Linux comm)")
	}
	if strings.IndexByte(v, 0) >= 0 {
		return "", fmt.Errorf("invalid process name")
	}
	return v, nil
}
func (s *Server) ebpfProcessAdd(w http.ResponseWriter, r *http.Request) {
	s.ebpfProcessMutate(w, r, false)
}
func (s *Server) ebpfProcessDelete(w http.ResponseWriter, r *http.Request) {
	s.ebpfProcessMutate(w, r, true)
}
func (s *Server) ebpfProcessMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	name, err := normalizeProcessName(x.Name)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	var cfg models.EBPFFastPathConfig
	if del {
		cfg, err = s.store.DelProcess(name, actor(r))
	} else {
		cfg, err = s.store.AddProcess(name, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist process rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

// normalizeCapabilityName validates against models.CapabilityBit's small,
// hand-picked set (CAP_NET_ADMIN/CAP_NET_RAW today) rather than accepting
// an arbitrary string — unlike process names, there's a fixed, known-safe
// vocabulary here and no reason to accept anything outside it.
func normalizeCapabilityName(v string) (string, error) {
	v = strings.ToUpper(strings.TrimSpace(v))
	if _, ok := models.CapabilityBit[v]; !ok {
		names := make([]string, 0, len(models.CapabilityBit))
		for n := range models.CapabilityBit {
			names = append(names, n)
		}
		sort.Strings(names)
		return "", fmt.Errorf("capability must be one of: %s", strings.Join(names, ", "))
	}
	return v, nil
}
func (s *Server) ebpfCapabilityAdd(w http.ResponseWriter, r *http.Request) {
	s.ebpfCapabilityMutate(w, r, false)
}
func (s *Server) ebpfCapabilityDelete(w http.ResponseWriter, r *http.Request) {
	s.ebpfCapabilityMutate(w, r, true)
}
func (s *Server) ebpfCapabilityMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &x, 1<<12); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	name, err := normalizeCapabilityName(x.Name)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	var cfg models.EBPFFastPathConfig
	if del {
		cfg, err = s.store.DelDeniedCapability(name, actor(r))
	} else {
		cfg, err = s.store.AddDeniedCapability(name, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist capability rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfAllowProcessAdd(w http.ResponseWriter, r *http.Request) {
	s.ebpfAllowProcessMutate(w, r, false)
}
func (s *Server) ebpfAllowProcessDelete(w http.ResponseWriter, r *http.Request) {
	s.ebpfAllowProcessMutate(w, r, true)
}
func (s *Server) ebpfAllowProcessMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	name, err := normalizeProcessName(x.Name)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	var cfg models.EBPFFastPathConfig
	if del {
		cfg, err = s.store.DelAllowedProcess(name, actor(r))
	} else {
		cfg, err = s.store.AddAllowedProcess(name, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist allow-process: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfSNIAdd(w http.ResponseWriter, r *http.Request)    { s.ebpfSNIMutate(w, r, false) }
func (s *Server) ebpfSNIDelete(w http.ResponseWriter, r *http.Request) { s.ebpfSNIMutate(w, r, true) }
func (s *Server) ebpfSNIMutate(w http.ResponseWriter, r *http.Request, del bool) {
	var x struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	name, err := normalizeDNSName(x.Name)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	var cfg models.EBPFFastPathConfig
	if del {
		cfg, err = s.store.DelSNI(name, actor(r))
	} else {
		cfg, err = s.store.AddSNI(name, actor(r))
	}
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist SNI rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

// validateRateLimit checks the shared PPS/BPS rules for EBPFRateLimit: PPS,
// when set, must be in the existing sane bound; BPS has no extra bound
// beyond its uint32 range; and at least one of the two must be set (an
// all-zero rule has no effect and is treated as delete by SetRateLimit).
func validateRateLimit(x *models.EBPFRateLimit) error {
	if x.PPS > 10000000 {
		return fmt.Errorf("pps must be between 1 and 10000000")
	}
	if x.PPS == 0 && x.BPS == 0 {
		return fmt.Errorf("at least one of pps or bps must be set")
	}
	return nil
}

func (s *Server) ebpfRateSet(w http.ResponseWriter, r *http.Request) {
	var x models.EBPFRateLimit
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	a, err := netip.ParseAddr(strings.TrimSpace(x.Destination))
	if err != nil {
		errorJSON(w, 400, "rate limiting requires an exact IPv4 or IPv6 destination")
		return
	}
	if err := validateRateLimit(&x); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	x.Destination = a.String()
	cfg, err := s.store.SetRateLimit(x, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist rate limit: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfRateDelete(w http.ResponseWriter, r *http.Request) {
	a, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		errorJSON(w, 400, "valid IPv4 or IPv6 address required")
		return
	}
	cfg, err := s.store.SetRateLimit(models.EBPFRateLimit{Destination: a.String()}, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist rate limit: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) ebpfShieldSet(w http.ResponseWriter, r *http.Request) {
	var x models.ShieldConfig
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	switch x.Mode {
	case "off", "audit", "enforce":
	default:
		errorJSON(w, 400, "mode must be off, audit, or enforce")
		return
	}
	for _, ip := range x.ProtectedIPv4 {
		a, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil || !a.Is4() {
			errorJSON(w, 400, "protectedIpv4 entries must be exact IPv4 addresses: "+ip)
			return
		}
	}
	for _, ip := range x.ProtectedIPv6 {
		a, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil || a.Is4() {
			errorJSON(w, 400, "protectedIpv6 entries must be exact IPv6 addresses: "+ip)
			return
		}
	}
	for _, pps := range []uint32{x.SynPPS, x.UDPPPS, x.ICMPPPS, x.OtherPPS} {
		if pps > 10000000 {
			errorJSON(w, 400, "pps thresholds must be at most 10000000 (0 disables that class)")
			return
		}
	}
	if x.BurstSeconds > 60 {
		errorJSON(w, 400, "burstSeconds must be at most 60")
		return
	}
	cfg, err := s.store.SetShield(x, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist shield config: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfNetPolConfigSet(w http.ResponseWriter, r *http.Request) {
	var x struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &x, 1<<12); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	cfg, err := s.store.SetNetPolEnabled(x.Enabled, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist NetPol config: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

// validateWorkloadScope trims and validates a workload selector in place —
// factored out of ebpfScope so the NetPol v2 endpoints (which also target
// workloads via EBPFWorkloadScope) validate identically rather than
// duplicating the checks with a chance to drift.
func validateWorkloadScope(sc *models.EBPFWorkloadScope) error {
	sc.Namespace, sc.Pod = strings.TrimSpace(sc.Namespace), strings.TrimSpace(sc.Pod)
	sc.WorkloadKind, sc.WorkloadName = strings.TrimSpace(sc.WorkloadKind), strings.TrimSpace(sc.WorkloadName)
	clean := map[string]string{}
	for k, v := range sc.Labels {
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" {
			return fmt.Errorf("scope label key cannot be empty")
		}
		clean[k] = v
	}
	sc.Labels = clean
	if sc.CgroupID == 0 && sc.Namespace == "" && sc.Pod == "" && sc.WorkloadKind == "" && sc.WorkloadName == "" && len(sc.Labels) == 0 {
		return fmt.Errorf("empty workload scope is not allowed")
	}
	return nil
}

func (s *Server) ebpfNetPolV2ConfigSet(w http.ResponseWriter, r *http.Request) {
	var x struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &x, 1<<12); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	cfg, err := s.store.SetNetPolV2Enabled(x.Enabled, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist NetPol v2 config: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfNetPolRuleAdd(w http.ResponseWriter, r *http.Request) {
	var x models.NetPolRule
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := validateWorkloadScope(&x.Selector); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	x.PeerIPv4 = strings.TrimSpace(x.PeerIPv4)
	if x.PeerIPv4 == "" {
		// Port-only allow-exception: any peer, exact port required — a
		// rule with neither an exact peer nor an exact port has no real
		// discriminator and is rejected here, not left to the BPF lookup
		// (netpol_v2_lookup4 has no "any-peer + any-port" fallback step).
		if x.Port == 0 {
			errorJSON(w, 400, "peerIpv4 or port is required (port-only rules need an exact port)")
			return
		}
	} else {
		a, err := netip.ParseAddr(x.PeerIPv4)
		if err != nil || !a.Is4() {
			errorJSON(w, 400, "peerIpv4 must be an exact IPv4 address, or empty for a port-only rule")
			return
		}
		x.PeerIPv4 = a.String()
	}
	var ok bool
	x.Protocol, ok = normalizeProtocol(x.Protocol)
	if !ok {
		errorJSON(w, 400, "protocol must be TCP, UDP, or ANY")
		return
	}
	x.Direction, ok = normalizeDirection(x.Direction)
	if !ok {
		errorJSON(w, 400, "direction must be ingress, egress, or both")
		return
	}
	x.Action = strings.ToLower(strings.TrimSpace(x.Action))
	if x.Action != "allow" && x.Action != "deny" {
		errorJSON(w, 400, "action must be allow or deny")
		return
	}
	cfg, err := s.store.AddNetPolRule(x, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist netpol rule: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfNetPolRuleDelete(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.DelNetPolRule(r.PathValue("id"), actor(r))
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
			return
		}
		errorJSON(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfConnRateLimitAdd(w http.ResponseWriter, r *http.Request) {
	var x models.EBPFConnRateLimit
	if err := decodeJSON(r, &x, 1<<16); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := validateWorkloadScope(&x.Selector); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if x.PerSecond == 0 {
		errorJSON(w, 400, "perSecond must be greater than zero")
		return
	}
	cfg, err := s.store.AddConnRateLimit(x, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist conn rate limit: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfConnRateLimitDelete(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.DelConnRateLimit(r.PathValue("id"), actor(r))
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
			return
		}
		errorJSON(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

type netPolDefaultDenyRequest struct {
	Selector models.EBPFWorkloadScope `json:"selector"`
	Enabled  bool                     `json:"enabled"`
	Lease    string                   `json:"lease,omitempty"`
}

// ebpfNetPolDefaultDenyPlan is the mandatory first step of activating
// default-deny for a workload selector: it never mutates state, only
// assesses risk and issues a preflight token (the same
// IssuePreflight/ConsumePreflight mechanism the CiliumNetworkPolicy
// plan/apply flow already uses, hash-bound to this exact request body).
// Deactivating (enabled=false) is always risk "low" — turning default-deny
// off is the fail-open direction and needs no risk gate.
func (s *Server) ebpfNetPolDefaultDenyPlan(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	var x netPolDefaultDenyRequest
	if err := json.Unmarshal(b, &x); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := validateWorkloadScope(&x.Selector); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	risk := "low"
	matched, allowCovered := 0, 0
	if x.Enabled {
		if s.kube == nil {
			errorJSON(w, http.StatusServiceUnavailable, "Kubernetes client unavailable")
			return
		}
		items, err := s.kube.ListWorkloads(r.Context(), "")
		if err != nil {
			errorJSON(w, 502, err.Error())
			return
		}
		cfg := s.store.Config()
		for _, pod := range items {
			if !workload.Match(x.Selector, pod) {
				continue
			}
			matched++
			for _, rule := range cfg.NetPolRules {
				if strings.EqualFold(rule.Action, "allow") && workload.Match(rule.Selector, pod) {
					allowCovered++
					break
				}
			}
		}
		if matched == 0 {
			errorJSON(w, 400, "no workloads match this selector")
			return
		}
		// Deliberately just the unambiguous binary check for now: zero
		// covering allow rules anywhere is a certain-outage config.
		// Partial-coverage ("some but not all matched workloads have an
		// allow rule") is a real "high" tier the design considered, but
		// needs a traffic-coverage heuristic beyond simple rule presence —
		// deferred rather than shipped as a guess.
		if allowCovered == 0 {
			risk = "critical"
		} else {
			risk = "medium"
		}
	}
	if risk == "critical" && r.URL.Query().Get("allowNoRules") != "true" {
		errorJSON(w, 409, fmt.Sprintf("%d matched workload(s) have zero allow rules covering them — this would certainly cut off their traffic; add allow rules first, or repeat with ?allowNoRules=true to override", matched))
		return
	}
	rcpt, err := s.store.IssuePreflight(b, risk, actor(r), 5*time.Minute)
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
		} else {
			errorJSON(w, 500, "could not issue preflight receipt")
		}
		return
	}
	writeJSON(w, 200, map[string]any{"risk": risk, "matchedWorkloads": matched, "workloadsWithAllowRule": allowCovered, "receipt": rcpt})
}

// ebpfNetPolDefaultDenySet is the second, gated step: unlike every other
// /ebpf/* mutation (and unlike even the general CiliumNetworkPolicy apply
// flow, which only requires preflight when s.requirePreflight is set), a
// fresh preflight token is unconditionally required here — this is the
// single highest-blast-radius mutation in the firewall feature.
func (s *Server) ebpfNetPolDefaultDenySet(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	var x netPolDefaultDenyRequest
	if err := json.Unmarshal(b, &x); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := validateWorkloadScope(&x.Selector); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	token := strings.TrimSpace(r.Header.Get("X-Netra-Plan-Token"))
	if token == "" {
		s.metricsData.preflightRejects.Add(1)
		errorJSON(w, http.StatusPreconditionRequired, "a fresh preflight receipt is required; run /api/v1/ebpf/netpol/default-deny/plan first")
		return
	}
	risk, ok, consumeErr := s.store.ConsumePreflight(token, b)
	if consumeErr != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist preflight consumption: "+consumeErr.Error())
		return
	}
	if !ok {
		s.metricsData.preflightRejects.Add(1)
		errorJSON(w, http.StatusPreconditionFailed, "preflight receipt is expired, already used, or does not match this exact request body")
		return
	}
	if risk == "high" || risk == "critical" {
		if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Netra-Confirm-Risk")), risk) {
			s.metricsData.preflightRejects.Add(1)
			errorJSON(w, 409, "preflight risk is "+risk+"; repeat plan and apply with X-Netra-Confirm-Risk: "+risk)
			return
		}
	}
	lease := 5 * time.Minute
	if x.Enabled && x.Lease != "" {
		d, err := time.ParseDuration(x.Lease)
		if err != nil || d < time.Minute || d > time.Hour {
			errorJSON(w, 400, "lease must be a duration between 1m and 60m")
			return
		}
		lease = d
	}
	cfg, err := s.store.SetNetPolDefaultDeny(x.Selector, x.Enabled, lease, actor(r))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist default-deny state: "+err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfRulesList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": s.store.ListRules()})
}

func (s *Server) ebpfRuleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, rule := range s.store.ListRules() {
		if rule.ID == id {
			writeJSON(w, 200, rule)
			return
		}
	}
	errorJSON(w, 404, "rule not found")
}

// ebpfRulePatch decodes and validates a PATCH body using exactly the same
// per-type checks as the corresponding legacy Add* handler (ebpfCIDRMutate,
// ebpfPortMutate, etc.) before handing a store.RuleEdit to Store.PatchRule
// — PATCH can never accept a value the value-keyed POST path would reject.
func (s *Server) ebpfRulePatch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	typ, ok := s.store.RuleType(id)
	if !ok {
		errorJSON(w, 404, "rule not found")
		return
	}
	var edit store.RuleEdit
	switch typ {
	case "ip4":
		var x struct {
			IP string `json:"ip"`
		}
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		a, err := netip.ParseAddr(strings.TrimSpace(x.IP))
		if err != nil || !a.Is4() {
			errorJSON(w, 400, "valid IPv4 required")
			return
		}
		edit.Str = a.String()
	case "ip6":
		var x struct {
			IP string `json:"ip"`
		}
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		a, err := netip.ParseAddr(strings.TrimSpace(x.IP))
		if err != nil || !a.Is6() || a.Is4In6() {
			errorJSON(w, 400, "valid IPv6 required")
			return
		}
		edit.Str = a.String()
	case "cidr":
		var x models.EBPFCIDRRule
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(x.CIDR))
		if err != nil {
			errorJSON(w, 400, "valid IPv4 or IPv6 CIDR required")
			return
		}
		x.CIDR = p.Masked().String()
		var dirOK bool
		x.Direction, dirOK = normalizeDirection(x.Direction)
		if !dirOK {
			errorJSON(w, 400, "direction must be ingress, egress, or both")
			return
		}
		edit.CIDR = x
	case "port":
		var x models.EBPFPortRule
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		if x.Port == 0 {
			errorJSON(w, 400, "port must be 1-65535")
			return
		}
		var ok bool
		x.Protocol, ok = normalizeProtocol(x.Protocol)
		if !ok {
			errorJSON(w, 400, "protocol must be TCP, UDP, or ANY")
			return
		}
		x.Direction, ok = normalizeDirection(x.Direction)
		if !ok {
			errorJSON(w, 400, "direction must be ingress, egress, or both")
			return
		}
		edit.Port = x
	case "uid":
		var x struct {
			UID uint32 `json:"uid"`
		}
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		edit.UID = x.UID
	case "dns", "sni":
		var x struct {
			Name string `json:"name"`
		}
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		name, err := normalizeDNSName(x.Name)
		if err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		edit.Str = name
	case "process":
		var x struct {
			Name string `json:"name"`
		}
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		name, err := normalizeProcessName(x.Name)
		if err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		edit.Str = name
	case "capability":
		var x struct {
			Name string `json:"name"`
		}
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		name, err := normalizeCapabilityName(x.Name)
		if err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		edit.Str = name
	case "rate":
		var x models.EBPFRateLimit
		if err := decodeJSON(r, &x, 1<<12); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		a, err := netip.ParseAddr(strings.TrimSpace(x.Destination))
		if err != nil {
			errorJSON(w, 400, "rate limiting requires an exact IPv4 or IPv6 destination")
			return
		}
		if err := validateRateLimit(&x); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		x.Destination = a.String()
		edit.Rate = x
	default:
		errorJSON(w, 400, "rule type "+typ+" does not support edit")
		return
	}
	cfg, err := s.store.PatchRule(id, edit, actor(r))
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
			return
		}
		errorJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfRuleDelete(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.DeleteRule(r.PathValue("id"), actor(r))
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
			return
		}
		errorJSON(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfRuleHistory(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	writeJSON(w, 200, map[string]any{"items": s.store.FirewallRuleHistory(r.PathValue("id"), limit)})
}

func (s *Server) ebpfRuleRollback(w http.ResponseWriter, r *http.Request) {
	revID, err := strconv.ParseUint(r.PathValue("revision"), 10, 64)
	if err != nil {
		errorJSON(w, 400, "valid revision id required")
		return
	}
	cfg, err := s.store.RollbackFirewallRule(r.PathValue("id"), revID, actor(r))
	if err != nil {
		if errors.Is(err, store.ErrPersistence) {
			s.metricsData.statePersistErrors.Add(1)
			errorJSON(w, http.StatusInsufficientStorage, err.Error())
			return
		}
		errorJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

func (s *Server) ebpfSummary(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, observability.Summarize(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), 10))
}
func (s *Server) ebpfHealth(w http.ResponseWriter, r *http.Request) {
	topN := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 200 {
			topN = n
		}
	}
	now := time.Now()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	resp := health.Build(agents, topN)
	stale := 0
	for _, a := range agents {
		if a.Stale {
			stale++
		}
	}
	s.store.RecordHealthSample(models.ClusterHealthSample{
		HealthScore: resp.Summary.HealthScore,
		AgentsStale: stale,
		Mode:        s.store.Config().Mode,
		Severity:    rollupHealthSeverity(resp.Summary.Anomalies),
	}, now)
	writeJSON(w, 200, resp)
}

// rollupHealthSeverity mirrors internal/ai.rollupSeverity's fold (critical
// wins outright, high folds into warning) but operates directly on
// NetworkHealthAnomaly rather than ai.Finding, since ebpfHealth has no
// reason to build a full ai.Snapshot just to get an overall severity.
func rollupHealthSeverity(anoms []models.NetworkHealthAnomaly) string {
	sev := "info"
	for _, a := range anoms {
		switch strings.ToLower(a.Severity) {
		case "critical":
			return "critical"
		case "warning", "high":
			sev = "warning"
		}
	}
	return sev
}
func (s *Server) ebpfCapDrift(w http.ResponseWriter, r *http.Request) {
	topN := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 200 {
			topN = n
		}
	}
	writeJSON(w, 200, capdrift.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), topN))
}

// ebpfNamespaceDrift mirrors ebpfCapDrift exactly, for the observe-only
// namespace-change watch (docs/exporter-tetragon-borrow-backlog.md's
// "Namespace-change watch" item — "Cap watch ships first; ns change can
// follow the same socket-owner scope").
func (s *Server) ebpfNamespaceDrift(w http.ResponseWriter, r *http.Request) {
	topN := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 200 {
			topN = n
		}
	}
	writeJSON(w, 200, nsdrift.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), topN))
}

// ebpfExeHashDrift mirrors ebpfCapDrift/ebpfNamespaceDrift exactly, for
// the observe-only half of "Exe-hash leased deny"
// (docs/exporter-tetragon-borrow-backlog.md).
func (s *Server) ebpfExeHashDrift(w http.ResponseWriter, r *http.Request) {
	topN := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 200 {
			topN = n
		}
	}
	writeJSON(w, 200, exehash.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), topN))
}
func (s *Server) ebpfPathDiagnostics(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	writeJSON(w, 200, pathdiag.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit))
}

func (s *Server) ebpfDropDetective(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, 200, detective.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), s.store.Config(), limit))
}

func (s *Server) ebpfDropDiagnostics(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	writeJSON(w, 200, dropdiag.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit))
}

func (s *Server) ebpfKernelNetworkDiagnostics(w http.ResponseWriter, r *http.Request) {
	window := 5 * time.Minute
	if raw := strings.TrimSpace(r.URL.Query().Get("window")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			errorJSON(w, http.StatusBadRequest, "window must be a positive duration such as 5m or 1h")
			return
		}
		window = parsed
	}
	writeJSON(w, 200, kerneldiag.BuildWindow(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), s.store.KernelNetworkWindows(window)))
}

func (s *Server) ebpfKernelNetworkSparkline(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.URL.Query().Get("node"))
	if node == "" {
		errorJSON(w, http.StatusBadRequest, "node is required")
		return
	}
	points := 30
	if n, err := strconv.Atoi(r.URL.Query().Get("points")); err == nil && n > 0 {
		points = n
	}
	writeJSON(w, 200, map[string]any{"node": node, "windows": s.store.KernelNetworkSparkline(node, points)})
}

func (s *Server) ebpfSysctlAudit(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	writeJSON(w, 200, sysctlaudit.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit))
}

// errDNSDetectDisabled/errScanDetectDisabled mirror errGitOpsDisabled's
// "optional feature, off unless configured" 409 convention.
var (
	errDNSDetectDisabled  = errors.New("dns-detect is not enabled (set NETRA_DNSDETECT_ENABLED=true)")
	errScanDetectDisabled = errors.New("scan-detect is not enabled (set NETRA_SCANDETECT_ENABLED=true)")
)

// ebpfDNSFindings reads from the shared *dnsdetect.Detector a cmd/netrad
// poller is continuously feeding (see WithDNSDetect) — unlike every other
// ebpf* handler in this file, this is not a fresh Build(agents) call: the
// detector holds its own rolling state (LRU + sliding time buckets) across
// requests, so two calls a minute apart can legitimately return different
// findings for the same underlying traffic.
func (s *Server) ebpfDNSFindings(w http.ResponseWriter, _ *http.Request) {
	if s.dnsDetector == nil {
		errorJSON(w, http.StatusConflict, errDNSDetectDisabled.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"findings": s.dnsDetector.Findings(),
		"snapshot": s.dnsDetector.Snapshot(),
	})
}

// ebpfScanFindings is scandetect's analog of ebpfDNSFindings above — same
// shared-detector-instance shape (see WithScanDetect).
func (s *Server) ebpfScanFindings(w http.ResponseWriter, _ *http.Request) {
	if s.scanDetector == nil {
		errorJSON(w, http.StatusConflict, errScanDetectDisabled.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"findings": s.scanDetector.Findings(),
		"snapshot": s.scanDetector.Snapshot(),
	})
}

func (s *Server) ebpfIPv6Diagnostics(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	writeJSON(w, 200, ipv6diag.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit))
}

func (s *Server) ebpfShieldDiagnostics(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	writeJSON(w, 200, shielddiag.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit))
}

func (s *Server) ebpfInterfaceFlows(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	writeJSON(w, 200, observability.InterfaceSummary(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit))
}

func (s *Server) ebpfL7(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	writeJSON(w, 200, l7.Build(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), limit))
}

// ebpfRuleLimits mirrors the hardcoded BPF map max_entries values in
// bpf/netra_tc.c — these are compile-time constants, not runtime-tunable,
// so raising any of them requires a source change and program reload.
var ebpfRuleLimits = map[string]int{
	"exactIPv4":           4096,                      // blocked_v4
	"exactIPv6":           4096,                      // blocked_v6
	"allowIPv4":           4096,                      // allowed_v4
	"allowIPv6":           4096,                      // allowed_v6
	"allowCidr":           8192,                      // allowed_cidr_v4 + allowed_cidr_v6 (each)
	"exactIngressIPv4":    4096,                      // blocked_ingress_v4
	"exactIngressIPv6":    4096,                      // blocked_ingress_v6
	"cidr":                8192,                      // blocked_cidr_v4 + blocked_cidr_v6 (each)
	"ports":               4096,                      // blocked_ports
	"allowPorts":          4096,                      // allowed_ports
	"uids":                4096,                      // blocked_uids
	"allowUids":           4096,                      // allowed_uids
	"dns":                 4096,                      // blocked_dns
	"sni":                 4096,                      // blocked_sni
	"processes":           4096,                      // blocked_comms
	"allowProcesses":      4096,                      // allowed_comms
	"rate":                4096,                      // rate_v4
	"netpol":              65536,                     // netpol_deny4
	"netpolV2Rules":       65536,                     // netpol_rules4
	"netpolV2DefaultDeny": 16384,                     // netpol_default4
	"connRateLimit":       4096,                      // conn_rate_limits (keyed by cgroup_id, not netpolV2Rules' peer)
	"capability":          len(models.CapabilityBit), // deniedCapabilities: bounded by the known-name vocabulary, not a BPF map size
}

func (s *Server) ebpfCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"standalone": true, "ciliumRequired": false, "hubbleOptional": true, "limits": ebpfRuleLimits, "hooks": []string{"cgroup_skb/ingress", "cgroup_skb/egress", "cgroup/connect4", "cgroup/connect6", "cgroup/sendmsg4", "cgroup/sendmsg6", "sockops", "tcx/ingress(optional)", "tcx/egress(optional)", "xdp(optional)", "raw_tracepoint/kfree_skb(optional)"}, "observability": []string{"IPv4/IPv6 flow counters", "ingress/egress direction", "TCP/UDP/ICMP protocol", "sampled flow headers", "DNS query names over UDP/53", "PID/UID/process comm on socket events", "cgroup ID", "namespace/pod/workload/container attribution", "TCP flags", "per-hook attribution", "TCP RTT/retransmit/RTO/connection health", "exact TCP SYN/FIN/RST signals", "DNS response latency and rcode health", "best-effort TLS ClientHello SNI metadata", "best-effort cleartext HTTP/1 method and Host metadata", "exact per-workload socket connection-attempt counters", "TCP connect-establishment latency", "sockops cwnd/packets-out pressure", "kernel lost_out/retrans_out/total_retrans transport signals", "sockops delivered-rate and TCP-state samples", "kernel skb drop-reason counters via optional skb:kfree_skb tracepoint", "conntrack for established flows", "policy-drop detective findings", "optional XDP shield PPS", "optional cgroup NetworkPolicy deny maps", "Linux softnet backlog/drop counters", "interface rx/tx drop/error/missed/no-handler counters", "ICMPv4/ICMPv6 type histograms", "node/interface-scoped ICMPv4/ICMPv6 error diagnostics (unreachable, time-exceeded, parameter-problem, MTU/packet-too-big)", "cgroup-attributed UDP flow packet/byte counters beyond DNS", "UDP/443 long-header packet counter (QUIC-observed traffic heuristic, not SNI extraction)"}, "enforcement": []string{"exact IPv4/IPv6 deny (egress, ingress, or both)", "optional SYN-drop mode per exact-IP deny entry (TCP-only, drops only new connection attempts)", "exact IPv4/IPv6 allow-exception (evaluated before deny/CIDR/port/rate)", "IPv4/IPv6 CIDR ingress/egress deny", "IPv4/IPv6 CIDR allow-exception (evaluated before deny/CIDR/port/rate)", "TCP/UDP/ANY port deny", "TCP/UDP/ANY port allow-exception (evaluated before deny/CIDR/port/rate)", "UID socket deny", "UID socket allow-exception", "process-name (comm) socket deny", "process-name (comm) socket allow-exception", "capability-gated socket deny (CAP_NET_RAW/CAP_NET_ADMIN, agent-sourced from a periodic /proc scan, TOCTOU-caveated)", "exact plain-DNS-name deny over UDP/53", "best-effort exact TLS SNI deny when ClientHello SNI is parsed", "IPv4/IPv6 destination PPS and/or independent BPS limit", "per-workload new-TCP-connection-rate ceiling (connect() only, UDP excluded)", "workload-scoped enforcement by namespace/pod/owner/labels/cgroup ID", "leased enforcement with fail-open", "optional XDP early ingress CIDR/port drop (global scope only)"}})
}

func (s *Server) agents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"items": s.store.AgentStatuses(time.Now(), s.agentStaleAfter), "staleAfterSeconds": int64(s.agentStaleAfter.Seconds())})
}
func (s *Server) agentReport(w http.ResponseWriter, r *http.Request) {
	var x models.AgentReport
	if err := decodeJSON(r, &x, 8<<20); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if x.Node == "" {
		errorJSON(w, 400, "node is required")
		return
	}
	// Set here, never read from the agent: it records how this report arrived.
	x.MTLS = mtls.Verified(r)
	s.store.Report(x)
	s.metricsData.agentReports.Add(1)
	if x.MTLS {
		s.metricsData.mtlsReports.Add(1)
	}
	if s.tlsFP != nil {
		for _, fp := range x.TLSFingerprints {
			if fp.JA3 == "" {
				continue
			}
			s.tlsFP.Observe(x.Node, tlsfp.Fingerprint{
				JA3: fp.JA3, JA4: fp.JA4, SNI: fp.SNI, ECH: fp.ECH,
			})
		}
	}
	writeJSON(w, 202, map[string]any{"accepted": true})
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	writeJSON(w, 200, map[string]any{"items": s.store.Audit(limit)})
}

func actor(r *http.Request) string {
	if who, ok := verifiedActor(r); ok {
		return who
	}
	if v := strings.TrimSpace(r.Header.Get("X-Netra-Actor")); v != "" {
		return v
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	if host == "" {
		return "api"
	}
	return "api:" + host
}

func (s *Server) serveWeb(w http.ResponseWriter, r *http.Request) {
	if s.webDir == "" {
		if r.URL.Path == "/" {
			writeJSON(w, 200, map[string]any{"name": "Netra", "api": "/api/v1/status"})
			return
		}
		http.NotFound(w, r)
		return
	}
	// Clean an absolute path so ".." cannot escape the web root, then require
	// the remainder to be a local relative path before touching the filesystem.
	clean := strings.TrimPrefix(filepath.Clean("/"+strings.TrimPrefix(r.URL.Path, "/")), "/")
	if clean == "" {
		clean = "index.html"
	}
	if !filepath.IsLocal(clean) {
		http.NotFound(w, r)
		return
	}
	p := filepath.Join(s.webDir, clean)
	if st, err := os.Stat(p); err != nil || st.IsDir() {
		p = filepath.Join(s.webDir, "index.html")
	}
	if ext := filepath.Ext(p); ext != "" {
		if ct := mime.TypeByExtension(ext); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
	}
	// Vite's build output hashes every filename under assets/ by content,
	// so those are safe to cache forever; index.html (and any SPA-routed
	// path that falls back to it above) names those hashed files, so it
	// must always be revalidated or a stale cached copy keeps pointing a
	// browser at old JS/CSS indefinitely — with no header here at all,
	// browsers apply heuristic caching and can do exactly that silently.
	if strings.Contains(p, string(os.PathSeparator)+"assets"+string(os.PathSeparator)) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeFile(w, r, p)
}
func decodeJSON(r *http.Request, v any, max int64) error {
	d := json.NewDecoder(io.LimitReader(r.Body, max))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeRawJSON(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
func errorJSON(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
func oneOfFold(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func requestLog(log *slog.Logger, metrics *telemetry, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		metrics.requests.Add(1)
		next.ServeHTTP(w, r)
		if r.URL.Path != "/healthz" {
			log.Info("http", "method", r.Method, "path", r.URL.Path, "duration", time.Since(started).String())
		}
	})
}
