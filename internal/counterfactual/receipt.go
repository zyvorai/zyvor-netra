// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Receipt is a signed, timestamped artifact recording the outcome of one
// evaluation. It is designed to be attached to a change request or a
// postmortem: unlike Result, its signature lets a third party verify
// that it wasn't altered after the fact, without needing access to
// whatever produced it.
//
// Verification is public-key based (Ed25519), not HMAC: anyone holding
// the signer's public key can verify a Receipt, but only the holder of
// the private key can produce one.
type Receipt struct {
	Result    *Result   `json:"result"`
	IssuedAt  time.Time `json:"issuedAt"`
	Issuer    string    `json:"issuer,omitempty"`
	PublicKey []byte    `json:"publicKey"`
	Signature []byte    `json:"signature"`
}

// signingPayload returns the bytes that get signed: everything in the
// receipt except the Signature field itself.
func (r *Receipt) signingPayload() ([]byte, error) {
	cp := *r
	cp.Signature = nil
	return json.Marshal(&cp)
}

// Signer produces signed Receipts. The zero value is not usable; build
// one with NewSigner or GenerateSigner.
type Signer struct {
	issuer string
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
}

// GenerateSigner creates a Signer with a freshly generated Ed25519 key
// pair. issuer is an opaque label recorded in every Receipt (e.g. a node
// name or service identity); it is not used for verification.
func GenerateSigner(issuer string) (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return &Signer{issuer: issuer, priv: priv, pub: pub}, nil
}

// NewSigner builds a Signer from an existing Ed25519 private key (e.g.
// loaded from a secret store). Returns an error if priv is not a valid
// Ed25519 private key size.
func NewSigner(issuer string, priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("counterfactual: invalid ed25519 private key size %d", len(priv))
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("counterfactual: could not derive public key")
	}
	return &Signer{issuer: issuer, priv: priv, pub: pub}, nil
}

// PublicKey returns the signer's public key, safe to distribute to
// verifiers.
func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.pub
}

// PublicKeyBase64 returns the public key base64-encoded, convenient for
// embedding in config or logs.
func (s *Signer) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.pub)
}

// Sign produces a Receipt for result, signed with s's private key.
func (s *Signer) Sign(result *Result) (*Receipt, error) {
	if result == nil {
		return nil, fmt.Errorf("counterfactual: nil result")
	}
	r := &Receipt{
		Result:    result,
		IssuedAt:  time.Now().UTC(),
		Issuer:    s.issuer,
		PublicKey: append([]byte(nil), s.pub...),
	}
	payload, err := r.signingPayload()
	if err != nil {
		return nil, fmt.Errorf("marshal signing payload: %w", err)
	}
	r.Signature = ed25519.Sign(s.priv, payload)
	return r, nil
}

// Verify checks a Receipt's signature against the public key it
// carries. It does NOT check that the embedded public key is one the
// caller trusts — callers that need that must additionally compare
// r.PublicKey against a known-good key (e.g. via VerifyWithKey).
func (r *Receipt) Verify() (bool, error) {
	return r.VerifyWithKey(r.PublicKey)
}

// VerifyWithKey checks a Receipt's signature against an explicitly
// supplied public key, ignoring whatever key is embedded in the
// receipt. This is the method callers should use when they have a
// trusted key from an out-of-band source (e.g. a config file), since it
// prevents a forged receipt from vouching for itself with its own
// attacker-supplied key.
func (r *Receipt) VerifyWithKey(pub ed25519.PublicKey) (bool, error) {
	if len(pub) != ed25519.PublicKeySize {
		return false, fmt.Errorf("counterfactual: invalid ed25519 public key size %d", len(pub))
	}
	payload, err := r.signingPayload()
	if err != nil {
		return false, fmt.Errorf("marshal signing payload: %w", err)
	}
	return ed25519.Verify(pub, payload, r.Signature), nil
}
