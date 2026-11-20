// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package chatops

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// replayWindow bounds how old (or how far in the future, to tolerate clock
// skew) an inbound Slack request's own timestamp may be before it's
// rejected as a possible replay.
const replayWindow = 5 * time.Minute

// VerifySlackSignature validates one inbound Slack request per Slack's own
// signing-secret scheme: HMAC-SHA256 over "v0:<timestamp>:<body>",
// hex-encoded and "v0="-prefixed, compared to signature in constant time.
// Uses the same crypto/hmac + crypto/sha256 primitives internal/webhook
// already imports for its own outbound signing — a different message
// format and header set, so the primitive is reused here, not that
// package's outbound Signer type.
func VerifySlackSignature(signingSecret, timestamp string, body []byte, signature string, now time.Time) error {
	if signingSecret == "" {
		return fmt.Errorf("chatops: no signing secret configured")
	}
	sec, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("chatops: invalid X-Slack-Request-Timestamp")
	}
	age := now.Sub(time.Unix(sec, 0))
	if age < 0 {
		age = -age
	}
	if age > replayWindow {
		return fmt.Errorf("chatops: request timestamp outside the %s replay window", replayWindow)
	}
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte("v0:" + timestamp + ":"))
	mac.Write(body)
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return fmt.Errorf("chatops: signature mismatch")
	}
	return nil
}
