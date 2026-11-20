// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7sample

import (
	"bytes"
	"strconv"
)

var httpMethods = set("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE")

// parseHTTP1 classifies an HTTP/1.x request (method, Host) or response (status).
// The request target, headers other than Host, cookies and bodies are never read
// into the result: a URL routinely carries tokens and identifiers.
func parseHTTP1(d []byte) (Obs, bool) {
	if len(d) >= 9 && bytes.HasPrefix(d, []byte("HTTP/1.")) {
		return parseHTTP1Response(d)
	}
	sp := bytes.IndexByte(d, ' ')
	if sp < 3 || sp > 8 {
		return Obs{}, false
	}
	method := string(d[:sp])
	if _, ok := httpMethods[method]; !ok {
		return Obs{}, false
	}
	// "<METHOD> <target> HTTP/1.x\r\n": require the version to be sure this is HTTP.
	eol := bytes.Index(d, []byte("\r\n"))
	if eol < 0 {
		eol = len(d)
	}
	line := d[:eol]
	if !bytes.Contains(line, []byte(" HTTP/1.")) {
		return Obs{}, false
	}
	return Obs{Proto: ProtoHTTP1, Kind: KindRequest, Op: method, Host: httpHost(d[eol:])}, true
}

func parseHTTP1Response(d []byte) (Obs, bool) {
	// "HTTP/1.1 200 OK": the status is the three digits after the first space.
	if d[8] != ' ' || len(d) < 12 {
		return Obs{}, false
	}
	code, err := strconv.Atoi(string(d[9:12]))
	if err != nil || code < 100 || code > 599 {
		return Obs{}, false
	}
	st := StatusOK
	if code >= 400 {
		st = StatusError
	}
	return Obs{Proto: ProtoHTTP1, Kind: KindResponse, Status: st, Code: strconv.Itoa(code)}, true
}

// httpHost extracts a validated Host header (without any port) from header lines.
func httpHost(headers []byte) string {
	for len(headers) > 0 {
		nl := bytes.IndexByte(headers, '\n')
		var line []byte
		if nl < 0 {
			line, headers = headers, nil
		} else {
			line, headers = headers[:nl], headers[nl+1:]
		}
		line = bytes.TrimRight(line, "\r")
		if len(line) > 6 && (line[0] == 'H' || line[0] == 'h') && bytes.EqualFold(line[:5], []byte("host:")) {
			return cleanHost(string(bytes.TrimSpace(line[5:])))
		}
	}
	return ""
}

// cleanHost returns h without a port if it is a plausible DNS name or IP literal,
// else "": anything that is not a hostname is dropped rather than stored.
func cleanHost(h string) string {
	if h == "" || len(h) > 255 {
		return ""
	}
	if h[0] != '[' { // strip :port (IPv6 literals keep their colons)
		if i := bytes.LastIndexByte([]byte(h), ':'); i >= 0 {
			h = h[:i]
		}
	}
	if h == "" {
		return ""
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == '[' || c == ']' || c == ':'
		if !ok {
			return ""
		}
	}
	out := []byte(h)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 32
		}
	}
	return string(out)
}
