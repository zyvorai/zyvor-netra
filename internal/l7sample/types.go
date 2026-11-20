// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package l7sample recognises application-protocol operations in the first bytes
// of sampled TCP payloads: Redis, PostgreSQL, MySQL, Kafka, HTTP/2 and gRPC, and
// HTTP/1. It exists so the agent can count what a workload is doing (GET vs SET,
// SELECT vs INSERT, which gRPC method, how often it errors) without proxying or
// storing traffic.
//
// Privacy is a property of the output, not a promise about the input. Parse
// returns an Obs whose every field is drawn from a fixed allowlist or a validated
// pattern: an operation *name*, a coarse status, a bounded error code. Keys, SQL
// text, topics, bodies, credentials and query strings are read only far enough to
// classify the message and never appear in an Obs, so nothing that could leak or
// explode metric cardinality leaves this package.
//
// The input is a sample, not a stream: a fragment of one packet, possibly
// starting mid-message. Parsers are stateless and best-effort, and say so through
// (Obs, ok): ok=false means "this is not something I can classify", never an
// error to surface.
package l7sample

// Protocol identifies an application protocol.
type Protocol uint8

const (
	ProtoUnknown Protocol = iota
	ProtoRedis
	ProtoPostgres
	ProtoMySQL
	ProtoKafka
	ProtoHTTP2 // includes gRPC
	ProtoHTTP1
	protoCount
)

var protoNames = [...]string{"unknown", "redis", "postgres", "mysql", "kafka", "http2", "http1"}

func (p Protocol) String() string {
	if int(p) < len(protoNames) {
		return protoNames[p]
	}
	return "unknown"
}

// ProtocolByName returns the protocol for a configuration name, or ProtoUnknown.
func ProtocolByName(name string) Protocol {
	for i, n := range protoNames {
		if i != 0 && n == name {
			return Protocol(i)
		}
	}
	if name == "grpc" {
		return ProtoHTTP2
	}
	return ProtoUnknown
}

// Kind says what a message is.
type Kind uint8

const (
	KindOther Kind = iota
	KindRequest
	KindResponse
)

func (k Kind) String() string {
	switch k {
	case KindRequest:
		return "request"
	case KindResponse:
		return "response"
	}
	return "other"
}

// Status is the coarse outcome of a response.
type Status uint8

const (
	StatusUnknown Status = iota
	StatusOK
	StatusError
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusError:
		return "error"
	}
	return ""
}

// Obs is one classified message. Every string field is from a fixed allowlist or
// a validated pattern; see the package comment.
type Obs struct {
	Proto  Protocol
	Kind   Kind
	Op     string // operation name: "GET", "SELECT", "Produce", "/pkg.Svc/Method"; "" for a response with none
	Status Status // responses only
	Code   string // bounded error/status code label: "ERR", "42", "grpc_14", "404"; "" when none
	// Host is the HTTP Host/:authority, validated as a hostname. Set only for
	// HTTP requests; callers must bound how many distinct values they keep.
	Host string
	// GRPC is true when the message is gRPC (HTTP/2 with an application/grpc
	// content type or a gRPC status).
	GRPC bool
}

// Parse classifies one sampled payload. toServer is true when the sample flows
// toward the well-known service port (a request direction), false when it flows
// back. It never panics on any input.
func Parse(p Protocol, toServer bool, data []byte) (Obs, bool) {
	if len(data) == 0 {
		return Obs{}, false
	}
	switch p {
	case ProtoRedis:
		return parseRedis(toServer, data)
	case ProtoPostgres:
		return parsePostgres(toServer, data)
	case ProtoMySQL:
		return parseMySQL(toServer, data)
	case ProtoKafka:
		return parseKafka(toServer, data)
	case ProtoHTTP2:
		return parseHTTP2(toServer, data)
	case ProtoHTTP1:
		return parseHTTP1(data)
	}
	return Obs{}, false
}

// upperWord returns the ASCII-uppercased leading letters/digits/underscore of b
// (at most max bytes), and whether the word was ended by something else (so it is
// a whole word, not a truncated one).
func upperWord(b []byte, max int) (string, bool) {
	n := 0
	for n < len(b) && n < max {
		c := b[n]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			n++
			continue
		}
		break
	}
	if n == 0 {
		return "", false
	}
	w := make([]byte, n)
	for i := 0; i < n; i++ {
		c := b[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		w[i] = c
	}
	return string(w), n < len(b) || n < max
}

// pick returns w when it is in the allowlist, else "OTHER". The allowlist is what
// bounds an operation label's cardinality.
func pick(allow map[string]struct{}, w string) string {
	if _, ok := allow[w]; ok {
		return w
	}
	return "OTHER"
}

func set(words ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(words))
	for _, w := range words {
		m[w] = struct{}{}
	}
	return m
}
