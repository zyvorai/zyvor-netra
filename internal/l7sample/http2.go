// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7sample

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"
)

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// grpcPath is a gRPC method path: /package.Service/Method. Anything else is not
// used as a label, so an arbitrary URL cannot become one.
var grpcPath = regexp.MustCompile(`^/[A-Za-z0-9_.]{1,100}/[A-Za-z0-9_]{1,64}$`)

// parseHTTP2 classifies HTTP/2 (and gRPC) from a sampled fragment. HPACK, the
// header compression, is stateful per connection, and a sample has none of that
// state: the first HEADERS on a connection decodes (its dynamic table is empty),
// later ones decode only if they do not reference dynamic-table entries. When a
// HEADERS frame cannot be decoded the result says so ("undecodable_headers")
// instead of guessing; how often that happens is itself reported.
func parseHTTP2(toServer bool, d []byte) (Obs, bool) {
	sawPreface := false
	if bytes.HasPrefix(d, []byte(h2Preface)) {
		if !toServer {
			return Obs{}, false
		}
		sawPreface = true
		d = d[len(h2Preface):]
	}
	for len(d) >= 9 {
		flen := int(d[0])<<16 | int(d[1])<<8 | int(d[2])
		ftype, flags := d[3], d[4]
		if flen > 1<<20 || ftype > 9 {
			return connectionOnly(sawPreface)
		}
		payload := d[9:]
		complete := len(payload) >= flen
		if complete {
			payload = payload[:flen]
		}
		if ftype == 0x1 && flags&0x4 != 0 { // HEADERS with END_HEADERS
			if !complete {
				return h2Undecodable(toServer)
			}
			return classifyHeaders(toServer, headerBlock(payload, flags))
		}
		if !complete {
			break
		}
		d = d[9+flen:]
	}
	return connectionOnly(sawPreface)
}

func connectionOnly(sawPreface bool) (Obs, bool) {
	if sawPreface {
		return Obs{Proto: ProtoHTTP2, Kind: KindRequest, Op: "connection"}, true
	}
	return Obs{}, false
}

func h2Undecodable(toServer bool) (Obs, bool) {
	k := KindResponse
	if toServer {
		k = KindRequest
	}
	return Obs{Proto: ProtoHTTP2, Kind: k, Op: "undecodable_headers"}, true
}

// headerBlock strips the optional padding and priority fields from a HEADERS
// payload, leaving the HPACK block.
func headerBlock(p []byte, flags byte) []byte {
	pad := 0
	if flags&0x8 != 0 { // PADDED
		if len(p) < 1 {
			return nil
		}
		pad = int(p[0])
		p = p[1:]
	}
	if flags&0x20 != 0 { // PRIORITY: 5 bytes
		if len(p) < 5 {
			return nil
		}
		p = p[5:]
	}
	if pad > len(p) {
		return nil
	}
	return p[:len(p)-pad]
}

func classifyHeaders(toServer bool, block []byte) (Obs, bool) {
	dec := hpack.NewDecoder(4096, nil)
	dec.SetMaxStringLength(2048)
	fields, err := dec.DecodeFull(block)
	if err != nil || len(fields) == 0 {
		return h2Undecodable(toServer)
	}
	var method, path, authority, status, ctype, grpcStatus string
	for _, f := range fields {
		switch f.Name {
		case ":method":
			method = f.Value
		case ":path":
			path = f.Value
		case ":authority":
			authority = f.Value
		case ":status":
			status = f.Value
		case "content-type":
			ctype = f.Value
		case "grpc-status":
			grpcStatus = f.Value
		}
	}
	isGRPC := strings.HasPrefix(ctype, "application/grpc") || grpcStatus != ""
	if toServer {
		if method == "" {
			return Obs{}, false
		}
		op := "OTHER"
		if _, ok := httpMethods[method]; ok {
			op = method
		}
		if isGRPC || strings.HasPrefix(ctype, "application/grpc") {
			op = "grpc"
			if grpcPath.MatchString(path) {
				op = path
			}
		}
		return Obs{Proto: ProtoHTTP2, Kind: KindRequest, Op: op, Host: cleanHost(authority), GRPC: isGRPC}, true
	}
	// gRPC: the outcome is in the trailers' grpc-status; the initial HEADERS
	// (":status 200") carries no outcome and is not counted as a response.
	if grpcStatus != "" {
		n, err := strconv.Atoi(grpcStatus)
		if err != nil || n < 0 || n > 16 {
			return Obs{}, false
		}
		st := StatusOK
		if n != 0 {
			st = StatusError
		}
		return Obs{Proto: ProtoHTTP2, Kind: KindResponse, Status: st, Code: "grpc_" + strconv.Itoa(n), GRPC: true}, true
	}
	if status == "" || isGRPC {
		return Obs{}, false
	}
	code, err := strconv.Atoi(status)
	if err != nil || code < 100 || code > 599 {
		return Obs{}, false
	}
	st := StatusOK
	if code >= 400 {
		st = StatusError
	}
	return Obs{Proto: ProtoHTTP2, Kind: KindResponse, Status: st, Code: strconv.Itoa(code)}, true
}
