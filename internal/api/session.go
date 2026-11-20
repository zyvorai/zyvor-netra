// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookie = "netra_session"
	sessionTTL    = 12 * time.Hour
)

// sessionCreate exchanges a valid API token for an HttpOnly session cookie.
// The cookie is an expiry plus an HMAC, not the token itself, so the dashboard
// does not have to keep the bearer in browser storage.
func (s *Server) sessionCreate(w http.ResponseWriter, r *http.Request) {
	if s.apiKey == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "authRequired": false})
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &body, 1<<16); err != nil {
		errorJSON(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !secureEq(strings.TrimSpace(body.Token), s.apiKey) {
		s.metricsData.authFailures.Add(1)
		errorJSON(w, http.StatusUnauthorized, "invalid API token")
		return
	}
	raw := s.mintSession(time.Now().Add(sessionTTL))
	setSessionCookie(w, r, raw, int(sessionTTL.Seconds()))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) sessionDelete(w http.ResponseWriter, r *http.Request) {
	setSessionCookie(w, r, "", -1)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) mintSession(exp time.Time) string {
	expUnix := exp.Unix()
	mac := hmac.New(sha256.New, []byte(s.apiKey))
	_, _ = mac.Write([]byte(strconv.FormatInt(expUnix, 10)))
	return strconv.FormatInt(expUnix, 10) + "." + hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) sessionValid(r *http.Request) bool {
	if s.apiKey == "" {
		return false
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	expStr, sig, ok := strings.Cut(c.Value, ".")
	if !ok || len(sig) != sha256.Size*2 {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	mac := hmac.New(sha256.New, []byte(s.apiKey))
	_, _ = mac.Write([]byte(expStr))
	want := hex.EncodeToString(mac.Sum(nil))
	return subtleConstantEq(sig, want)
}

func subtleConstantEq(got, want string) bool {
	return len(got) == len(want) && hmac.Equal([]byte(got), []byte(want))
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})
}
