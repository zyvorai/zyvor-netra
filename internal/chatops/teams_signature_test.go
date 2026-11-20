// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package chatops

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// teamsTestFixture serves a local OpenID config + JWKS (mirroring Bot
// Framework's own discovery document shape) backed by an in-test RSA
// keypair, so signature verification tests never touch the real
// login.botframework.com.
type teamsTestFixture struct {
	priv    *rsa.PrivateKey
	kid     string
	jwksSrv *httptest.Server
	metaSrv *httptest.Server
}

func newTeamsTestFixture(t *testing.T) *teamsTestFixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &teamsTestFixture{priv: priv, kid: "test-kid-1"}
	f.jwksSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reads f.priv/f.kid at request time, not just at fixture-creation
		// time, so TestTeamsVerifyRefetchesOnKeyRotation can rotate the key
		// the JWKS serves out from under an already-built verifier.
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{jwkFor(f.kid, &f.priv.PublicKey)}})
	}))
	t.Cleanup(f.jwksSrv.Close)
	f.metaSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jwks_uri": f.jwksSrv.URL})
	}))
	t.Cleanup(f.metaSrv.Close)
	return f
}

func jwkFor(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func (f *teamsTestFixture) verifier(appID string) *TeamsVerifier {
	return &TeamsVerifier{appID: appID, openIDConfigURL: f.metaSrv.URL, httpClient: http.DefaultClient, now: time.Now}
}

func signTestJWT(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func validTeamsClaims(appID string) map[string]any {
	return map[string]any{"iss": botFrameworkIssuer, "aud": appID, "exp": time.Now().Add(time.Hour).Unix()}
}

func TestTeamsVerifyValid(t *testing.T) {
	f := newTeamsTestFixture(t)
	v := f.verifier("app-123")
	tok := signTestJWT(t, f.priv, f.kid, validTeamsClaims("app-123"))
	if err := v.Verify(tok); err != nil {
		t.Fatalf("expected a valid token to verify, got %v", err)
	}
}

func TestTeamsVerifyWrongAudience(t *testing.T) {
	f := newTeamsTestFixture(t)
	v := f.verifier("app-123")
	tok := signTestJWT(t, f.priv, f.kid, validTeamsClaims("some-other-app"))
	if err := v.Verify(tok); err == nil {
		t.Fatal("expected a token with the wrong audience to be rejected")
	}
}

func TestTeamsVerifyWrongIssuer(t *testing.T) {
	f := newTeamsTestFixture(t)
	v := f.verifier("app-123")
	claims := validTeamsClaims("app-123")
	claims["iss"] = "https://not-bot-framework.example"
	tok := signTestJWT(t, f.priv, f.kid, claims)
	if err := v.Verify(tok); err == nil {
		t.Fatal("expected a token with the wrong issuer to be rejected")
	}
}

func TestTeamsVerifyExpired(t *testing.T) {
	f := newTeamsTestFixture(t)
	v := f.verifier("app-123")
	claims := validTeamsClaims("app-123")
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	tok := signTestJWT(t, f.priv, f.kid, claims)
	if err := v.Verify(tok); err == nil {
		t.Fatal("expected an expired token to be rejected")
	}
}

func TestTeamsVerifyMalformedToken(t *testing.T) {
	f := newTeamsTestFixture(t)
	v := f.verifier("app-123")
	if err := v.Verify("not-a-jwt"); err == nil {
		t.Fatal("expected a malformed (non 3-part) token to be rejected")
	}
}

func TestTeamsVerifyMalformedHeaderEncoding(t *testing.T) {
	f := newTeamsTestFixture(t)
	v := f.verifier("app-123")
	if err := v.Verify("not-base64!!.eyJhIjoxfQ.sig"); err == nil {
		t.Fatal("expected a token with an unparseable header segment to be rejected")
	}
}

func TestTeamsVerifyUnsupportedAlg(t *testing.T) {
	f := newTeamsTestFixture(t)
	v := f.verifier("app-123")
	header, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT", "kid": f.kid})
	body, _ := json.Marshal(validTeamsClaims("app-123"))
	tok := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body) + "."
	if err := v.Verify(tok); err == nil {
		t.Fatal("expected an alg:none token to be rejected")
	}
}

func TestTeamsVerifyWrongKey(t *testing.T) {
	f := newTeamsTestFixture(t)
	v := f.verifier("app-123")
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Signed by a key never published in the fixture's JWKS, but claiming
	// the same kid the JWKS does have — must fail signature verification,
	// not silently accept whichever key happens to be under that kid.
	tok := signTestJWT(t, other, f.kid, validTeamsClaims("app-123"))
	if err := v.Verify(tok); err == nil {
		t.Fatal("expected a token signed by an unpublished key to be rejected")
	}
}

func TestTeamsVerifyUnknownKeyID(t *testing.T) {
	f := newTeamsTestFixture(t)
	v := f.verifier("app-123")
	tok := signTestJWT(t, f.priv, "no-such-kid", validTeamsClaims("app-123"))
	if err := v.Verify(tok); err == nil {
		t.Fatal("expected a token with an unknown key id to be rejected")
	}
}

func TestTeamsVerifyRefetchesOnKeyRotation(t *testing.T) {
	f := newTeamsTestFixture(t)
	v := f.verifier("app-123")
	tok := signTestJWT(t, f.priv, f.kid, validTeamsClaims("app-123"))
	if err := v.Verify(tok); err != nil {
		t.Fatalf("expected the first token to verify, got %v", err)
	}
	// Rotate to a brand new key/kid the verifier has never seen — its
	// cached JWKS won't have it, so Verify must refetch rather than fail
	// closed on a stale cache.
	newPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.kid = "test-kid-2"
	f.priv = newPriv
	tok2 := signTestJWT(t, newPriv, f.kid, validTeamsClaims("app-123"))
	if err := v.Verify(tok2); err != nil {
		t.Fatalf("expected verification to refetch and succeed for a rotated key, got %v", err)
	}
}
