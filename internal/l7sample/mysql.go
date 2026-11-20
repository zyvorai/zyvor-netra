// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7sample

import "encoding/binary"

// MySQL packets: 3-byte little-endian payload length, 1-byte sequence id, payload.
// A client command is sequence 0 and starts with a command byte.
func parseMySQL(toServer bool, d []byte) (Obs, bool) {
	if len(d) < 5 {
		return Obs{}, false
	}
	plen := int(d[0]) | int(d[1])<<8 | int(d[2])<<16
	seq := d[3]
	if plen == 0 || plen > 1<<24-1 {
		return Obs{}, false
	}
	p := d[4:]
	if toServer {
		if seq != 0 {
			return Obs{}, false // handshake response and continuations: not classified
		}
		req := func(op string) (Obs, bool) { return Obs{Proto: ProtoMySQL, Kind: KindRequest, Op: op}, true }
		switch p[0] {
		case 0x01:
			return req("quit")
		case 0x02:
			return req("init_db")
		case 0x03: // COM_QUERY
			return req(sqlVerb(p[1:]))
		case 0x04:
			return req("field_list")
		case 0x0e:
			return req("ping")
		case 0x16:
			return req("stmt_prepare")
		case 0x17:
			return req("stmt_execute")
		case 0x19:
			return req("stmt_close")
		case 0x1b:
			return req("set_option")
		}
		return Obs{}, false
	}
	resp := func(op string, st Status, code string) (Obs, bool) {
		return Obs{Proto: ProtoMySQL, Kind: KindResponse, Op: op, Status: st, Code: code}, true
	}
	switch {
	case seq == 0 && p[0] == 0x0a: // server greeting, protocol version 10
		return resp("handshake", StatusUnknown, "")
	case p[0] == 0x00:
		return resp("", StatusOK, "")
	case p[0] == 0xff && len(p) >= 3:
		return resp("", StatusError, mysqlErrClass(binary.LittleEndian.Uint16(p[1:3])))
	case p[0] == 0xfe && plen < 9:
		return resp("", StatusOK, "") // EOF
	case seq >= 1:
		return resp("", StatusOK, "") // a result-set packet
	}
	return Obs{}, false
}

// mysqlErrClass maps an error number to a small fixed label set.
func mysqlErrClass(n uint16) string {
	switch n {
	case 1045, 1044, 1142, 1143:
		return "access_denied"
	case 1064, 1149:
		return "syntax"
	case 1146, 1054, 1049, 1051:
		return "no_such_object"
	case 1062, 1048, 1452, 1451, 1216, 1217:
		return "constraint"
	case 1205, 1213:
		return "lock_or_deadlock"
	case 1040, 1203, 1226, 1461:
		return "resource_limit"
	case 2002, 2003, 2006, 2013, 1053, 1317:
		return "connection"
	}
	return "other"
}
