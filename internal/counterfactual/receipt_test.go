// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignAndVerifyRoundTrip(t *testing.T) {
	signer, err := GenerateSigner("netrad-node-1")
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	result := &Result{PolicyName: "test", PolicyHash: "abc123"}

	receipt, err := signer.Sign(result)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if receipt.Issuer != "netrad-node-1" {
		t.Fatalf("unexpected issuer: %s", receipt.Issuer)
	}

	ok, err := receipt.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatalf("expected valid signature")
	}

	ok, err = receipt.VerifyWithKey(signer.PublicKey())
	if err != nil {
		t.Fatalf("verify with key: %v", err)
	}
	if !ok {
		t.Fatalf("expected valid signature against signer's own key")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	signer, err := GenerateSigner("issuer")
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	receipt, err := signer.Sign(&Result{PolicyName: "test"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	receipt.Result.PolicyName = "tampered"

	ok, err := receipt.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatalf("expected tampered receipt to fail verification")
	}
}

func TestVerifyWithKeyRejectsForgedEmbeddedKey(t *testing.T) {
	// A forged receipt carries an attacker-generated key that "verifies"
	// against itself; VerifyWithKey against the real trusted key must
	// reject it.
	real, err := GenerateSigner("real")
	if err != nil {
		t.Fatalf("generate real signer: %v", err)
	}
	forged, err := GenerateSigner("real") // same issuer label, different key
	if err != nil {
		t.Fatalf("generate forged signer: %v", err)
	}

	receipt, err := forged.Sign(&Result{PolicyName: "test"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// The forged receipt verifies fine against its own embedded key...
	ok, err := receipt.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatalf("expected forged receipt to self-verify")
	}

	// ...but must fail when checked against the real, trusted key.
	ok, err = receipt.VerifyWithKey(real.PublicKey())
	if err != nil {
		t.Fatalf("verify with real key: %v", err)
	}
	if ok {
		t.Fatalf("expected forged receipt to fail verification against trusted key")
	}
}

func TestNewSignerRejectsBadKeySize(t *testing.T) {
	_, err := NewSigner("issuer", make([]byte, 10))
	if err == nil {
		t.Fatalf("expected error for undersized key")
	}
}

func TestVerifyWithKeyRejectsBadKeySize(t *testing.T) {
	signer, err := GenerateSigner("issuer")
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	receipt, err := signer.Sign(&Result{})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := receipt.VerifyWithKey(make([]byte, 4)); err == nil {
		t.Fatalf("expected error for undersized verification key")
	}
}

func TestNewSignerFromRawKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := NewSigner("issuer", priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	if signer.PublicKeyBase64() == "" {
		t.Fatalf("expected non-empty public key base64")
	}
	receipt, err := signer.Sign(&Result{})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := receipt.VerifyWithKey(pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatalf("expected valid signature against externally supplied key")
	}
}
