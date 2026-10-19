package api

import (
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/mtls"
	"github.com/zyvorai/netra/internal/mtls/mtlstest"
	"github.com/zyvorai/netra/internal/store"
)

// mtlsEnv is the real handler behind a real TLS listener configured the way
// netrad configures its own, so what is under test is the handshake plus the
// route policy together, not either alone.
type mtlsEnv struct {
	ca  *mtlstest.CA
	srv *httptest.Server
	st  *store.Store
	s   *Server
}

func newMTLSEnv(t *testing.T, mode string) *mtlsEnv {
	t.Helper()
	ca := mtlstest.NewCA(t, "agents")
	t.Setenv("NETRA_API_KEY", "api-key")
	t.Setenv("NETRA_AGENT_KEY", "agent-key")
	t.Setenv("NETRA_METRICS_TOKEN", "")
	t.Setenv("NETRA_AGENT_MTLS", mode)
	t.Setenv("NETRA_AGENT_CLIENT_CA", ca.CAFile)
	m, cfg, err := mtls.FromEnv(true)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "" && string(m) != mode {
		t.Fatalf("mode = %q", m)
	}
	sp := ca.Server(t)
	cert, err := tls.LoadX509KeyPair(sp.CertFile, sp.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg.Certificates = []tls.Certificate{cert}
	st := store.New()
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, st)
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &mtlsEnv{ca: ca, srv: srv, st: st, s: s}
}

// do sends a request; cert (may be empty) is the client certificate's name.
func (e *mtlsEnv) do(t *testing.T, method, path, body string, hdr map[string]string, certCN string) int {
	t.Helper()
	cfg, err := mtls.ClientConfig(e.ca.CAFile, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if certCN != "" {
		p := e.ca.Client(t, certCN)
		if cfg, err = mtls.ClientConfig(e.ca.CAFile, p.CertFile, p.KeyFile, false); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, e.srv.URL+path, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

var agentKey = map[string]string{"X-Netra-Agent-Key": "agent-key"}

const reportBody = `{"node":"n1","observedAt":"2026-01-01T00:00:00Z","mtls":true}`

func agentMTLSFlag(e *mtlsEnv, node string) (found, flag bool) {
	for _, a := range e.st.Agents() {
		if a.Node == node {
			return true, a.MTLS
		}
	}
	return false, false
}

func TestRequiredModeRejectsAnAgentKeyWithoutACertificate(t *testing.T) {
	e := newMTLSEnv(t, "required")
	if code := e.do(t, "POST", "/api/v1/agents/report", reportBody, agentKey, ""); code != 401 {
		t.Fatalf("correct key, no certificate: %d, want 401", code)
	}
	if found, _ := agentMTLSFlag(e, "n1"); found {
		t.Fatal("a report refused for lacking a certificate was stored")
	}
	if got := e.s.metricsData.mtlsRejected.Load(); got != 1 {
		t.Fatalf("rejected counter = %d, want 1", got)
	}
}

func TestRequiredModeStillNeedsTheAgentKey(t *testing.T) {
	e := newMTLSEnv(t, "required")
	// The certificate is a second factor, not a replacement.
	if code := e.do(t, "POST", "/api/v1/agents/report", reportBody, map[string]string{"X-Netra-Agent-Key": "wrong"}, "agent-1"); code != 401 {
		t.Fatalf("valid certificate, wrong key: %d, want 401", code)
	}
	if code := e.do(t, "POST", "/api/v1/agents/report", reportBody, nil, "agent-1"); code != 401 {
		t.Fatalf("valid certificate, no key: %d, want 401", code)
	}
}

func TestRequiredModeAcceptsKeyPlusCertificateAndMarksTheReport(t *testing.T) {
	e := newMTLSEnv(t, "required")
	if code := e.do(t, "POST", "/api/v1/agents/report", reportBody, agentKey, "agent-1"); code != 202 {
		t.Fatalf("key + certificate: %d, want 202", code)
	}
	found, flag := agentMTLSFlag(e, "n1")
	if !found || !flag {
		t.Fatalf("report stored=%v mtls=%v, want both true", found, flag)
	}
	if e.s.metricsData.mtlsReports.Load() != 1 {
		t.Fatal("mtls report counter not incremented")
	}
}

func TestTheMTLSFlagIsSetByTheControllerNotClaimedByTheAgent(t *testing.T) {
	e := newMTLSEnv(t, "optional")
	// The body claims mtls:true but the connection has no certificate.
	if code := e.do(t, "POST", "/api/v1/agents/report", reportBody, agentKey, ""); code != 202 {
		t.Fatalf("optional mode must accept an agent without a certificate: %d", code)
	}
	if found, flag := agentMTLSFlag(e, "n1"); !found || flag {
		t.Fatalf("stored=%v mtls=%v: an agent's own claim of mtls must be overwritten with what the handshake proved", found, flag)
	}
}

func TestOptionalModeVerifiesOfferedCertificatesAndRecordsThem(t *testing.T) {
	e := newMTLSEnv(t, "optional")
	if code := e.do(t, "POST", "/api/v1/agents/report", `{"node":"withcert","observedAt":"2026-01-01T00:00:00Z"}`, agentKey, "agent-1"); code != 202 {
		t.Fatalf("%d", code)
	}
	if _, flag := agentMTLSFlag(e, "withcert"); !flag {
		t.Fatal("optional mode did not record that the certificate verified")
	}
}

func TestOffModeIsExactlyTheOldBehaviour(t *testing.T) {
	e := newMTLSEnv(t, "")
	if code := e.do(t, "POST", "/api/v1/agents/report", reportBody, agentKey, ""); code != 202 {
		t.Fatalf("default: %d, want 202", code)
	}
	if _, flag := agentMTLSFlag(e, "n1"); flag {
		t.Fatal("mtls flagged with the feature off")
	}
}

func TestRequiredModeGuardsTheAgentKeyPathOnSharedRoutesOnly(t *testing.T) {
	e := newMTLSEnv(t, "required")
	const p = "/api/v1/ebpf/config" // accepts an agent key or an API credential
	if code := e.do(t, "GET", p, "", agentKey, ""); code != 401 {
		t.Fatalf("agent key without a certificate: %d, want 401", code)
	}
	if code := e.do(t, "GET", p, "", agentKey, "agent-1"); code != 200 {
		t.Fatalf("agent key with a certificate: %d, want 200", code)
	}
	// People are unaffected: an API key from a browser or netractl has no client cert.
	if code := e.do(t, "GET", p, "", map[string]string{"Authorization": "Bearer api-key"}, ""); code != 200 {
		t.Fatalf("API key without a certificate: %d, want 200 (mTLS is for agents)", code)
	}
}

func TestRequiredModeDoesNotLockOutTheRestOfTheAPI(t *testing.T) {
	e := newMTLSEnv(t, "required")
	for _, p := range []string{"/healthz", "/livez"} {
		if code := e.do(t, "GET", p, "", nil, ""); code != 200 {
			t.Errorf("%s without a certificate: %d, want 200 (kubelet probes carry none)", p, code)
		}
	}
	if code := e.do(t, "GET", "/api/v1/agents", "", map[string]string{"Authorization": "Bearer api-key"}, ""); code != 200 {
		t.Errorf("agents list with an API key and no certificate: %d", code)
	}
}

func TestBindNodeRejectsMismatch(t *testing.T) {
	t.Setenv("NETRA_AGENT_MTLS_BIND_NODE", "true")
	e := newMTLSEnv(t, "required")
	p := e.ca.ClientNode(t, "worker-a")
	cfg, err := mtls.ClientConfig(e.ca.CAFile, p.CertFile, p.KeyFile, false)
	if err != nil {
		t.Fatal(err)
	}
	post := func(body string) int {
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/agents/report", strings.NewReader(body))
		req.Header.Set("X-Netra-Agent-Key", "agent-key")
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if code := post(`{"node":"other-node","observedAt":"2026-01-01T00:00:00Z"}`); code != 403 {
		t.Fatalf("mismatch: %d want 403", code)
	}
	if e.s.metricsData.mtlsNodeMismatch.Load() < 1 {
		t.Fatal("mismatch counter not incremented")
	}
	if code := post(`{"node":"worker-a","observedAt":"2026-01-01T00:00:00Z"}`); code != 202 {
		t.Fatalf("match: %d want 202", code)
	}
}

func TestDenySerialRejects(t *testing.T) {
	e := newMTLSEnv(t, "required")
	p := e.ca.ClientNode(t, "n1")
	denyPath := t.TempDir() + "/deny.txt"
	if err := os.WriteFile(denyPath, []byte(e.ca.LastSerial()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.s.mtlsDeny = mtls.NewDenyList(denyPath)
	cfg, err := mtls.ClientConfig(e.ca.CAFile, p.CertFile, p.KeyFile, false)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/agents/report", strings.NewReader(reportBody))
	req.Header.Set("X-Netra-Agent-Key", "agent-key")
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("denied serial: %d want 403", resp.StatusCode)
	}
	if e.s.metricsData.mtlsDeniedSerial.Load() < 1 {
		t.Fatal("denied serial counter not incremented")
	}
}

func TestAnInvalidModeFailsClosed(t *testing.T) {
	t.Setenv("NETRA_API_KEY", "k")
	t.Setenv("NETRA_AGENT_KEY", "a")
	t.Setenv("NETRA_AGENT_MTLS", "requried") // typo
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, store.New())
	if s.agentMTLS != mtls.Required {
		t.Fatalf("a typo'd NETRA_AGENT_MTLS gave %q; it must not weaken the policy", s.agentMTLS)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/agents/report", strings.NewReader(reportBody))
	req.Header.Set("X-Netra-Agent-Key", "a")
	s.Handler().ServeHTTP(rec, req) // plain request: no TLS state at all
	if rec.Code != 401 {
		t.Fatalf("code %d, want 401", rec.Code)
	}
}
