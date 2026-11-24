// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package incidentbundle

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SealSchema identifies a detached seal document.
const SealSchema = "netra-incident-seal/1"

// MinSealKeyBytes is the shortest key Seal accepts.
const MinSealKeyBytes = 16

// Seal is a detached HMAC-SHA256 attestation over a bundle hash chain head.
// The hash chain alone only makes edits visible: anyone who can rewrite the
// file can recompute it. A seal adds a keyed tag that only a holder of the
// shared key can produce, so a recipient with the same key can tell the bundle
// is the one the sealer saw. It is symmetric (not a public-key signature, no
// non-repudiation) and the key is never stored in the seal or the bundle.
type Seal struct {
	Schema      string `json:"schema"`
	Algorithm   string `json:"algorithm"`
	BundleHead  string `json:"bundleHead"`
	WindowStart string `json:"windowStart"`
	WindowEnd   string `json:"windowEnd"`
	KeyID       string `json:"keyId"`
	SealedAt    string `json:"sealedAt"`
	MAC         string `json:"mac"`
}

func sealKeyID(key []byte) string {
	h := sha256.Sum256(append([]byte("netra-incident-seal-keyid\n"), key...))
	return hex.EncodeToString(h[:4])
}

func sealMAC(key []byte, head, start, end string) string {
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "%s\n%s\n%s\n%s", SealSchema, head, start, end)
	return hex.EncodeToString(m.Sum(nil))
}

func firstOf(l []string) string {
	if len(l) == 0 {
		return "unknown problem"
	}
	return l[0]
}

// loadVerified returns the decoded bundle only when the file verifies.
func loadVerified(data []byte) (*Bundle, error) {
	raw, problems, err := Load(data)
	if err != nil {
		return nil, err
	}
	if len(problems) > 0 {
		return nil, errors.New("bundle archive does not verify: " + problems[0])
	}
	if rep := VerifyFile(data); !rep.OK {
		return nil, errors.New("bundle does not verify: " + firstOf(rep.Problems))
	}
	var doc Bundle
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// SealBundle verifies the bundle (one that does not verify is never sealed)
// and returns a seal over its chain head and window.
func SealBundle(data, key []byte, now time.Time) (Seal, error) {
	if len(key) < MinSealKeyBytes {
		return Seal{}, fmt.Errorf("seal key must be at least %d bytes", MinSealKeyBytes)
	}
	doc, err := loadVerified(data)
	if err != nil {
		return Seal{}, err
	}
	return Seal{
		Schema: SealSchema, Algorithm: "hmac-sha256", BundleHead: doc.Integrity.Head,
		WindowStart: doc.Window.Start, WindowEnd: doc.Window.End,
		KeyID: sealKeyID(key), SealedAt: now.UTC().Format(time.RFC3339),
		MAC: sealMAC(key, doc.Integrity.Head, doc.Window.Start, doc.Window.End),
	}, nil
}

// VerifySeal checks that the bundle verifies, the seal names this bundle and
// the tag was produced with key. It fails closed on any mismatch.
func VerifySeal(data, sealJSON, key []byte) error {
	if len(key) < MinSealKeyBytes {
		return fmt.Errorf("seal key must be at least %d bytes", MinSealKeyBytes)
	}
	var s Seal
	dec := json.NewDecoder(bytes.NewReader(sealJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return fmt.Errorf("seal is not a valid seal document: %w", err)
	}
	if s.Schema != SealSchema || s.Algorithm != "hmac-sha256" {
		return fmt.Errorf("unsupported seal schema %q or algorithm %q", s.Schema, s.Algorithm)
	}
	doc, err := loadVerified(data)
	if err != nil {
		return err
	}
	if s.BundleHead != doc.Integrity.Head || s.WindowStart != doc.Window.Start || s.WindowEnd != doc.Window.End {
		return errors.New("seal is for a different bundle (chain head or window differs)")
	}
	if s.KeyID != sealKeyID(key) {
		return errors.New("seal was made with a different key (key id differs)")
	}
	got, err := hex.DecodeString(strings.TrimSpace(s.MAC))
	want, _ := hex.DecodeString(sealMAC(key, doc.Integrity.Head, doc.Window.Start, doc.Window.End))
	if err != nil || !hmac.Equal(got, want) {
		return errors.New("seal MAC does not match: wrong key or altered seal")
	}
	return nil
}
