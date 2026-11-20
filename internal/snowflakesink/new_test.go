// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package snowflakesink

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// generateTestKeyPair writes an unencrypted PKCS#8-PEM RSA private key
// to a temp file (matching loadPrivateKey's expected format, and
// Snowflake's own key-pair setup docs) and returns its path alongside
// the key itself for JWT verification.
func generateTestKeyPair(t *testing.T) (path string, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8 key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path = filepath.Join(t.TempDir(), "snowflake_key.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path, key
}

// TestNewConnectsAuthenticatesAndEnsuresTableAgainstFakeServer exercises
// New end to end — DSN construction, sql.Open, the gosnowflake driver's
// real JWT key-pair authentication handshake, PingContext, and
// ensureTable's CREATE TABLE/ALTER TABLE — against a fake Snowflake REST
// server instead of a live account. This is the one path
// internal/snowflakesink's other (sqlmock-based) tests cannot reach,
// since they build a Sink around an already-open, already-authenticated
// *sql.DB.
func TestNewConnectsAuthenticatesAndEnsuresTableAgainstFakeServer(t *testing.T) {
	keyPath, privKey := generateTestKeyPair(t)
	fake := newFakeSnowflakeServer(t)

	cfg := Config{
		Account:        "testacct",
		User:           "netra_svc",
		PrivateKeyPath: keyPath,
		Warehouse:      "wh",
		Database:       "db",
		Schema:         "sch",
		Table:          "netra_audit",
		ExtraColumns:   []ExtraColumn{{Name: "reason", Source: "details:reason"}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sink, err := newWithDialTarget(ctx, cfg, slog.New(slog.DiscardHandler), fake.dialTarget(t))
	if err != nil {
		t.Fatalf("newWithDialTarget: %v", err)
	}
	defer func() {
		if err := sink.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	assertJWTAuthenticatedCorrectly(t, fake.lastAuth(), privKey, cfg.Account, "TESTACCT", "NETRA_SVC")

	executed := fake.executedSQL()
	if !containsSubstring(executed, "CREATE TABLE IF NOT EXISTS NETRA_AUDIT") {
		t.Fatalf("executed statements = %v, want a CREATE TABLE IF NOT EXISTS NETRA_AUDIT", executed)
	}
	if !containsSubstring(executed, "ALTER TABLE NETRA_AUDIT ADD COLUMN IF NOT EXISTS REASON STRING") {
		t.Fatalf("executed statements = %v, want the configured extra column's ALTER TABLE", executed)
	}
}

func containsSubstring(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// assertJWTAuthenticatedCorrectly verifies the login-request New() sent
// really is a validly signed JWT for the configured account/user — not
// just that some string was sent — by checking it verifies against the
// key pair's own public half and carries the exact iss/sub claim shape
// gosnowflake's prepareJWTToken documents (auth.go). Key-pair (JWT) auth
// carries no LOGIN_NAME/PASSWORD in the outer request body at all —
// account and user identity live entirely inside the signed JWT's
// iss/sub claims (wantAccountUpper/wantUserUpper), so that's what's
// checked against, separately from the raw, as-configured account name
// gosnowflake echoes back in ACCOUNT_NAME.
func assertJWTAuthenticatedCorrectly(t *testing.T, auth authRequestBody, key *rsa.PrivateKey, wantRawAccount, wantAccountUpper, wantUserUpper string) {
	t.Helper()
	if auth.Data.Authenticator != "SNOWFLAKE_JWT" {
		t.Fatalf("authenticator = %q, want SNOWFLAKE_JWT", auth.Data.Authenticator)
	}
	if auth.Data.AccountName != wantRawAccount {
		t.Fatalf("account name = %q, want %q", auth.Data.AccountName, wantRawAccount)
	}
	if auth.Data.Token == "" {
		t.Fatal("login request carried no JWT in TOKEN")
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(auth.Data.Token, claims, func(*jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("JWT did not verify against the configured private key's public half: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	fingerprint := sha256.Sum256(pubDER)
	wantIss := wantAccountUpper + "." + wantUserUpper + ".SHA256:" + base64.StdEncoding.EncodeToString(fingerprint[:])
	wantSub := wantAccountUpper + "." + wantUserUpper
	if got, _ := claims["iss"].(string); got != wantIss {
		t.Fatalf("jwt iss = %q, want %q", got, wantIss)
	}
	if got, _ := claims["sub"].(string); got != wantSub {
		t.Fatalf("jwt sub = %q, want %q", got, wantSub)
	}
}
