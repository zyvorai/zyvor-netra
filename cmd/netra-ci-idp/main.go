// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Command netra-ci-idp is a throwaway OpenID Connect provider for CI. It
// serves discovery and a JWKS and mints signed tokens on request, so
// scripts/ci-oidc-live.sh can drive a real netrad through OIDC login without a
// real identity provider.
//
// It is NOT a real IdP: /token hands a signed token to anyone who asks. It is
// therefore built only by that script (the Dockerfiles copy specific commands,
// not this one) and it refuses to listen on anything but loopback.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18091", "loopback address to listen on")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("bad -addr: %v", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		log.Fatalf("refusing to listen on %q: this helper mints tokens for anyone and must stay on loopback", *addr)
	}
	issuer := "http://" + *addr

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	const kid = "ci-key-1"
	var down atomic.Bool

	mux := http.NewServeMux()
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if down.Load() {
				http.Error(w, "idp down (simulated)", http.StatusServiceUnavailable)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/.well-known/openid-configuration", guard(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": issuer + "/jwks"})
	}))
	mux.HandleFunc("/jwks", guard(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))

	// GET /token?roles=admin,viewer&sub=u1&email=a@b&aud=netra&ttl=3600&iss=...
	// ttl may be negative to mint an already-expired token; iss and aud can be
	// overridden to mint deliberately wrong ones.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		ttl := 3600
		if v := q.Get("ttl"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				http.Error(w, "bad ttl", http.StatusBadRequest)
				return
			}
			ttl = n
		}
		claims := jwt.MapClaims{
			"iss": firstNonEmpty(q.Get("iss"), issuer),
			"aud": firstNonEmpty(q.Get("aud"), "netra"),
			"sub": firstNonEmpty(q.Get("sub"), "ci-user"),
			"exp": time.Now().Add(time.Duration(ttl) * time.Second).Unix(),
			"iat": time.Now().Unix(),
		}
		if e := q.Get("email"); e != "" {
			claims["email"] = e
		}
		if roles := q.Get("roles"); roles != "" {
			claims["roles"] = strings.Split(roles, ",")
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		signed, err := tok.SignedString(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, signed)
	})

	// GET /down?on=1 makes discovery and JWKS answer 503; on=0 restores them.
	mux.HandleFunc("/down", func(w http.ResponseWriter, r *http.Request) {
		down.Store(r.URL.Query().Get("on") == "1")
		fmt.Fprintf(w, "down=%v\n", down.Load())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") })

	log.Printf("netra-ci-idp listening on %s (issuer %s)", *addr, issuer)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
