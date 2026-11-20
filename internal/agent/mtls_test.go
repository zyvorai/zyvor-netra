package agent

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/mtls"
	"github.com/zyvorai/netra/internal/mtls/mtlstest"
)

// mtlsController is a TLS listener that refuses anything without a verified
// client certificate, as netrad does in NETRA_AGENT_MTLS=required.
func mtlsController(t *testing.T, ca *mtlstest.CA, onWS func(*websocket.Conn)) *httptest.Server {
	t.Helper()
	cfg, err := mtls.ServerConfig(mtls.Required, ca.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	sp := ca.Server(t)
	cert, err := tls.LoadX509KeyPair(sp.CertFile, sp.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Certificates = []tls.Certificate{cert}
	up := websocket.Upgrader{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mtls.Verified(r) {
			http.Error(w, "certificate required", http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/capture/stream") {
			c, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer c.Close()
			onWS(c)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newAgentFor(t *testing.T, srv *httptest.Server, env map[string]string) *Agent {
	t.Helper()
	t.Setenv("NETRA_SERVER", srv.URL)
	t.Setenv("NETRA_AGENT_KEY", "k")
	for _, k := range []string{"NETRA_TLS_INSECURE", "NETRA_CA_FILE", "NETRA_CLIENT_CERT", "NETRA_CLIENT_KEY"} {
		t.Setenv(k, env[k])
	}
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestAgentReportsPresentTheClientCertificate(t *testing.T) {
	ca := mtlstest.NewCA(t, "agents")
	srv := mtlsController(t, ca, func(*websocket.Conn) {})
	p := ca.Client(t, "agent-1")

	a := newAgentFor(t, srv, map[string]string{"NETRA_CA_FILE": ca.CAFile, "NETRA_CLIENT_CERT": p.CertFile, "NETRA_CLIENT_KEY": p.KeyFile})
	if err := a.report(context.Background(), models.AgentReport{Node: "n1"}); err != nil {
		t.Fatalf("report with a client certificate: %v", err)
	}

	// The same controller with the certificate withheld: refused, and refused
	// loudly (an agent that silently sent nothing would look healthy).
	bare := newAgentFor(t, srv, map[string]string{"NETRA_CA_FILE": ca.CAFile})
	err := bare.report(context.Background(), models.AgentReport{Node: "n1"})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("report without a certificate: %v, want a 401", err)
	}
}

func TestCaptureStreamDialAlsoPresentsTheClientCertificate(t *testing.T) {
	ca := mtlstest.NewCA(t, "agents")
	got := make(chan []byte, 1)
	srv := mtlsController(t, ca, func(c *websocket.Conn) {
		if _, b, err := c.ReadMessage(); err == nil {
			got <- b
		}
	})
	p := ca.Client(t, "agent-1")
	a := newAgentFor(t, srv, map[string]string{"NETRA_CA_FILE": ca.CAFile, "NETRA_CLIENT_CERT": p.CertFile, "NETRA_CLIENT_KEY": p.KeyFile})

	url := "wss" + strings.TrimPrefix(srv.URL, "https") + "/api/v1/agents/capture/stream?node=n1"
	conn, _, err := a.wsDialer.DialContext(context.Background(), url, nil)
	if err != nil {
		t.Fatalf("websocket dial with a client certificate: %v", err)
	}
	defer conn.Close()
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("frame")); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		if string(b) != "frame" {
			t.Fatalf("got %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the controller never received the frame")
	}

	bare := newAgentFor(t, srv, map[string]string{"NETRA_CA_FILE": ca.CAFile})
	if c, _, err := bare.wsDialer.DialContext(context.Background(), url, nil); err == nil {
		c.Close()
		t.Fatal("the capture stream connected without a client certificate")
	}
}

func TestAgentRefusesToRunWithAnUnusableCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	a := newAgentFor(t, srv, map[string]string{"NETRA_CLIENT_CERT": "/no/such.crt", "NETRA_CLIENT_KEY": "/no/such.key"})
	err := a.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "TLS configuration") {
		t.Fatalf("Run = %v; an agent the controller will reject on every report must not start quietly", err)
	}
}

func TestAgentWithNoMTLSSettingsKeepsTheOldTransport(t *testing.T) {
	a := newAgentFor(t, httptest.NewTLSServer(http.NotFoundHandler()), map[string]string{})
	if a.http.Transport != nil {
		t.Fatalf("with no TLS settings the client must use the default transport, got %T", a.http.Transport)
	}
	insecure := newAgentFor(t, httptest.NewTLSServer(http.NotFoundHandler()), map[string]string{"NETRA_TLS_INSECURE": "true"})
	tr, ok := insecure.http.Transport.(*http.Transport)
	if !ok || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("NETRA_TLS_INSECURE=true no longer skips verification")
	}
}
