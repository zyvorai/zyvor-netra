// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package snowflakesink

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
)

// fakeSnowflakeServer is a minimal stand-in for Snowflake's REST API,
// just enough of it for gosnowflake's key-pair (JWT) authenticator and
// query-submission path to complete successfully against a real
// (non-mocked) HTTP round trip. It exists so CI can exercise New's
// actual DSN-building, JWT-signing, and query-submission code — the
// parts internal/snowflakesink's sqlmock-based tests never touch,
// since they construct a Sink around an already-open *sql.DB — without
// a live Snowflake account or credentials.
//
// It intentionally does not implement Snowflake's real SQL semantics:
// every query-request is answered with a generic, empty-data success
// response (see execHandler), which is enough for New's own CREATE
// TABLE/ALTER TABLE/PingContext calls to succeed. Anything this server
// doesn't recognize (heartbeats, telemetry) also gets a generic success
// response rather than a 404, since gosnowflake's own retry/backoff
// around a real error would otherwise slow tests down for no benefit.
type fakeSnowflakeServer struct {
	srv *httptest.Server

	mu        sync.Mutex
	authBody  authRequestBody // the most recent login-request body
	execSQL   []string        // every sqlText this server was asked to run, in order
	authCalls int
}

type authRequestBody struct {
	Data struct {
		AccountName   string `json:"ACCOUNT_NAME"`
		LoginName     string `json:"LOGIN_NAME"`
		Authenticator string `json:"AUTHENTICATOR"`
		Token         string `json:"TOKEN"`
	} `json:"data"`
}

type execRequestBody struct {
	SQLText string `json:"sqlText"`
}

func newFakeSnowflakeServer(t *testing.T) *fakeSnowflakeServer {
	t.Helper()
	f := &fakeSnowflakeServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/session/v1/login-request", f.handleLogin)
	mux.HandleFunc("/queries/v1/query-request", f.handleExec)
	mux.HandleFunc("/session", func(w http.ResponseWriter, r *http.Request) {
		writeJSONSuccess(w, map[string]any{})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Heartbeats, telemetry, and anything else gosnowflake might
		// call in the background: a generic success keeps those paths
		// from erroring/retrying without this server having to model
		// them for real.
		writeJSONSuccess(w, map[string]any{})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// dialTarget points sink.New's DSN at this fake server instead of a
// real Snowflake account host.
func (f *fakeSnowflakeServer) dialTarget(t *testing.T) dialTarget {
	t.Helper()
	u, err := url.Parse(f.srv.URL)
	if err != nil {
		t.Fatalf("parse fake server URL: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split fake server host/port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse fake server port: %v", err)
	}
	return dialTarget{host: host, port: port, protocol: "http"}
}

func (f *fakeSnowflakeServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body authRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.authBody = body
	f.authCalls++
	f.mu.Unlock()
	writeJSONSuccess(w, map[string]any{
		"token":                   "fake-session-token",
		"masterToken":             "fake-master-token",
		"sessionId":               1,
		"validityInSeconds":       3600,
		"masterValidityInSeconds": 14400,
	})
}

func (f *fakeSnowflakeServer) handleExec(w http.ResponseWriter, r *http.Request) {
	var body execRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.execSQL = append(f.execSQL, body.SQLText)
	f.mu.Unlock()
	// StatementTypeID and RowSet are both deliberately left zero-valued:
	// gosnowflake's ExecContext only calls updateRows (which needs a
	// non-nil RowSet) when isDml(StatementTypeID) is true, and Ping
	// discards this response entirely — a bare "success" is sufficient
	// for every query New() issues (SELECT 1, CREATE TABLE, ALTER TABLE).
	writeJSONSuccess(w, map[string]any{})
}

func (f *fakeSnowflakeServer) executedSQL() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.execSQL))
	copy(out, f.execSQL)
	return out
}

func (f *fakeSnowflakeServer) lastAuth() authRequestBody {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authBody
}

func writeJSONSuccess(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":    data,
		"success": true,
		"code":    "",
		"message": "",
	})
}
