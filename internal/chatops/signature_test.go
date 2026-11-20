// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package chatops

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

func sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + timestamp + ":"))
	mac.Write(body)
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySlackSignatureValid(t *testing.T) {
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	body := []byte("command=/netra&text=status")
	sig := sign("shh", ts, body)
	if err := VerifySlackSignature("shh", ts, body, sig, now); err != nil {
		t.Fatalf("expected valid signature to verify, got %v", err)
	}
}

func TestVerifySlackSignatureWrongSecret(t *testing.T) {
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	body := []byte("command=/netra")
	sig := sign("shh", ts, body)
	if err := VerifySlackSignature("different", ts, body, sig, now); err == nil {
		t.Fatal("expected signature mismatch with the wrong secret")
	}
}

func TestVerifySlackSignatureTamperedBody(t *testing.T) {
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	sig := sign("shh", ts, []byte("command=/netra&text=status"))
	if err := VerifySlackSignature("shh", ts, []byte("command=/netra&text=mode+enforce"), sig, now); err == nil {
		t.Fatal("expected signature mismatch for a tampered body")
	}
}

func TestVerifySlackSignatureExpiredTimestamp(t *testing.T) {
	old := time.Now().Add(-10 * time.Minute)
	ts := strconv.FormatInt(old.Unix(), 10)
	body := []byte("command=/netra")
	sig := sign("shh", ts, body)
	if err := VerifySlackSignature("shh", ts, body, sig, time.Now()); err == nil {
		t.Fatal("expected a timestamp outside the replay window to be rejected")
	}
}

func TestVerifySlackSignatureFutureTimestampAlsoRejected(t *testing.T) {
	future := time.Now().Add(10 * time.Minute)
	ts := strconv.FormatInt(future.Unix(), 10)
	body := []byte("command=/netra")
	sig := sign("shh", ts, body)
	if err := VerifySlackSignature("shh", ts, body, sig, time.Now()); err == nil {
		t.Fatal("expected a far-future timestamp to be rejected too")
	}
}

func TestVerifySlackSignatureNoSecretConfigured(t *testing.T) {
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	if err := VerifySlackSignature("", ts, []byte("x"), "v0=anything", now); err == nil {
		t.Fatal("expected an error when no signing secret is configured")
	}
}

func TestVerifySlackSignatureMalformedTimestamp(t *testing.T) {
	if err := VerifySlackSignature("shh", "not-a-number", []byte("x"), "v0=anything", time.Now()); err == nil {
		t.Fatal("expected an error for a non-numeric timestamp")
	}
}
