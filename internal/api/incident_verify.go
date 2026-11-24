// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/incidentbundle"
)

// maxIncidentUpload bounds a bundle posted for verification or a report: the
// bundle's own 8 MiB cap plus the JSON wrapper and tar overhead.
const maxIncidentUpload = incidentbundle.MaxFileBytes + 1<<20

// sealKeyEnv holds the controller-side seal key. The key is never accepted in
// a request and never returned.
const sealKeyEnv = "NETRA_INCIDENT_SEAL_KEY"

func serverSealKey() []byte {
	return []byte(strings.TrimSpace(os.Getenv(sealKeyEnv)))
}

// readIncidentUpload returns the bundle bytes from a request body that is
// either the bundle itself (JSON or tar.gz) or {"bundle": <object or string>}
// (the wrapper MCP tools use).
func readIncidentUpload(w http.ResponseWriter, r *http.Request) (data []byte, seal string, ok bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxIncidentUpload))
	if err != nil || len(bytes.TrimSpace(body)) == 0 {
		errorJSON(w, http.StatusBadRequest, "send an incident bundle as the request body")
		return nil, "", false
	}
	t := bytes.TrimSpace(body)
	if t[0] == '{' {
		var wrap struct {
			Bundle json.RawMessage `json:"bundle"`
			Seal   json.RawMessage `json:"seal"`
		}
		if json.Unmarshal(t, &wrap) == nil && len(wrap.Bundle) > 0 {
			unwrap := func(raw json.RawMessage) string {
				var str string
				if json.Unmarshal(raw, &str) == nil {
					return str
				}
				return string(raw)
			}
			if len(wrap.Seal) > 0 {
				seal = unwrap(wrap.Seal)
			}
			return []byte(unwrap(wrap.Bundle)), seal, true
		}
	}
	return body, "", true
}

// incidentVerify serves POST /api/v1/incident/verify: the same fail-closed
// check as `netractl incident verify`, on a bundle the caller sends. With an
// X-Netra-Incident-Seal header or a "seal" field (a seal document) it also checks the seal
// against the controller's NETRA_INCIDENT_SEAL_KEY. Read-only: nothing is
// stored and no key is accepted or returned.
func (s *Server) incidentVerify(w http.ResponseWriter, r *http.Request) {
	data, bodySeal, ok := readIncidentUpload(w, r)
	if !ok {
		return
	}
	rep := incidentbundle.VerifyFile(data)
	out := map[string]any{"verify": rep}
	sealDoc := strings.TrimSpace(r.Header.Get("X-Netra-Incident-Seal"))
	if sealDoc == "" {
		sealDoc = strings.TrimSpace(bodySeal)
	}
	if sealDoc != "" {
		key := serverSealKey()
		if len(key) == 0 {
			errorJSON(w, http.StatusBadRequest, "no seal key is configured on the controller ("+sealKeyEnv+"); verify the seal offline with netractl incident verify --seal")
			return
		}
		res := map[string]any{"checked": true, "ok": true}
		if err := incidentbundle.VerifySeal(data, []byte(sealDoc), key); err != nil {
			res["ok"] = false
			res["error"] = err.Error()
		}
		out["seal"] = res
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// incidentReport serves POST /api/v1/incident/report?format=json|markdown: a
// deterministic post-incident draft from a bundle that verifies. It adds no
// data; a bundle that does not verify is refused (422).
func (s *Server) incidentReport(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "markdown" {
		errorJSON(w, http.StatusBadRequest, "format must be json or markdown")
		return
	}
	data, _, ok := readIncidentUpload(w, r)
	if !ok {
		return
	}
	rep, err := incidentbundle.BuildReport(data)
	if err != nil {
		errorJSON(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if format == "markdown" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, rep.Markdown())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// sealHeader adds X-Netra-Incident-Seal for a freshly built bundle when the
// request asked for it (seal=true) and the controller holds a key.
func sealHeader(w http.ResponseWriter, bundle []byte) (string, bool) {
	key := serverSealKey()
	if len(key) == 0 {
		return "no seal key is configured on the controller (" + sealKeyEnv + ")", false
	}
	seal, err := incidentbundle.SealBundle(bundle, key, time.Now())
	if err != nil {
		return "could not seal the bundle: " + err.Error(), false
	}
	b, _ := json.Marshal(seal)
	w.Header().Set("X-Netra-Incident-Seal", string(b))
	return "", true
}
