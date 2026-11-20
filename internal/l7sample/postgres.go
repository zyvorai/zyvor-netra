// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7sample

import "encoding/binary"

func parsePostgres(toServer bool, d []byte) (Obs, bool) {
	if toServer {
		return parsePostgresFrontend(d)
	}
	return parsePostgresBackend(d)
}

// Frontend (client) messages. A startup packet has no type byte: int32 length,
// then an int32 request code. Everything else is type byte + int32 length.
func parsePostgresFrontend(d []byte) (Obs, bool) {
	if len(d) >= 8 {
		l := binary.BigEndian.Uint32(d[0:4])
		if l >= 8 && l <= 10000 {
			switch binary.BigEndian.Uint32(d[4:8]) {
			case 196608: // protocol 3.0
				return Obs{Proto: ProtoPostgres, Kind: KindRequest, Op: "startup"}, true
			case 80877103:
				return Obs{Proto: ProtoPostgres, Kind: KindRequest, Op: "ssl_request"}, true
			case 80877104:
				return Obs{Proto: ProtoPostgres, Kind: KindRequest, Op: "gss_request"}, true
			case 80877102:
				return Obs{Proto: ProtoPostgres, Kind: KindRequest, Op: "cancel"}, true
			}
		}
	}
	if len(d) < 5 {
		return Obs{}, false
	}
	l := binary.BigEndian.Uint32(d[1:5])
	if l < 4 || l > 1<<30 {
		return Obs{}, false
	}
	body := d[5:]
	req := func(op string) (Obs, bool) { return Obs{Proto: ProtoPostgres, Kind: KindRequest, Op: op}, true }
	switch d[0] {
	case 'Q': // simple query: SQL text
		return req(sqlVerb(body))
	case 'P': // Parse: statement name\0 query\0 ...
		if z := indexByte(body, 0); z >= 0 {
			return req(sqlVerb(body[z+1:]))
		}
		return req("parse")
	case 'B':
		return req("bind")
	case 'E':
		return req("execute")
	case 'D':
		return req("describe")
	case 'C':
		return req("close")
	case 'S':
		return req("sync")
	case 'H':
		return req("flush")
	case 'X':
		return req("terminate")
	case 'F':
		return req("function_call")
	case 'p':
		return req("auth") // password / SASL response: never read
	case 'd', 'c', 'f':
		return req("copy_data")
	}
	return Obs{}, false
}

// Backend (server) messages: type byte + int32 length.
func parsePostgresBackend(d []byte) (Obs, bool) {
	if len(d) < 5 {
		return Obs{}, false
	}
	l := binary.BigEndian.Uint32(d[1:5])
	if l < 4 || l > 1<<30 {
		return Obs{}, false
	}
	body := d[5:]
	resp := func(op string, st Status, code string) (Obs, bool) {
		return Obs{Proto: ProtoPostgres, Kind: KindResponse, Op: op, Status: st, Code: code}, true
	}
	switch d[0] {
	case 'E': // ErrorResponse: fields of (byte code, cstring); C = SQLSTATE
		return resp("", StatusError, pgSQLState(body))
	case 'C': // CommandComplete: "SELECT 5", "INSERT 0 1"
		return resp(sqlVerb(body), StatusOK, "")
	case 'R': // Authentication*: int32 code, 0 = ok
		if len(body) >= 4 && binary.BigEndian.Uint32(body[:4]) == 0 {
			return resp("auth", StatusOK, "")
		}
		return resp("auth", StatusUnknown, "")
	case 'Z':
		return resp("ready", StatusOK, "")
	case 'T', 'D', '1', '2', '3', 'n', 't', 's', 'I', 'S', 'K', 'N', 'A', 'G', 'H', 'W', 'c', 'd':
		return resp("", StatusOK, "")
	}
	return Obs{}, false
}

// pgSQLState returns the two-character SQLSTATE class of an ErrorResponse
// (e.g. "42" for syntax/access errors, "23" integrity violation, "57" operator
// intervention), or "other". Classes are a small fixed set, so the label is
// bounded; the message text is never read.
func pgSQLState(b []byte) string {
	for i := 0; i < len(b); {
		f := b[i]
		if f == 0 {
			break
		}
		i++
		end := indexByte(b[i:], 0)
		if end < 0 {
			break
		}
		if f == 'C' && end >= 2 {
			c := b[i : i+2]
			if isAlnum(c[0]) && isAlnum(c[1]) {
				return string(c)
			}
		}
		i += end + 1
	}
	return "other"
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
