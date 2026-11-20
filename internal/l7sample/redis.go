// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7sample

import "bytes"

// redisCommands bounds the operation label. It is the commonly used set; a
// command outside it is reported as OTHER rather than as a new label.
var redisCommands = set(
	"GET", "SET", "DEL", "EXISTS", "EXPIRE", "PEXPIRE", "TTL", "PTTL", "INCR", "DECR", "INCRBY", "DECRBY", "APPEND",
	"MGET", "MSET", "SETNX", "SETEX", "PSETEX", "GETSET", "GETDEL", "GETEX", "STRLEN", "KEYS", "SCAN", "TYPE", "RENAME",
	"HGET", "HSET", "HMGET", "HMSET", "HDEL", "HGETALL", "HEXISTS", "HINCRBY", "HKEYS", "HVALS", "HLEN", "HSCAN",
	"LPUSH", "RPUSH", "LPOP", "RPOP", "LRANGE", "LLEN", "LINDEX", "LREM", "LTRIM", "BLPOP", "BRPOP", "RPOPLPUSH",
	"SADD", "SREM", "SMEMBERS", "SISMEMBER", "SCARD", "SPOP", "SUNION", "SINTER", "SDIFF", "SSCAN",
	"ZADD", "ZREM", "ZRANGE", "ZRANGEBYSCORE", "ZREVRANGE", "ZSCORE", "ZCARD", "ZINCRBY", "ZRANK", "ZCOUNT", "ZSCAN",
	"PUBLISH", "SUBSCRIBE", "UNSUBSCRIBE", "PSUBSCRIBE", "PUNSUBSCRIBE", "XADD", "XREAD", "XREADGROUP", "XACK", "XRANGE", "XLEN", "XGROUP",
	"MULTI", "EXEC", "DISCARD", "WATCH", "UNWATCH", "EVAL", "EVALSHA", "SCRIPT", "FUNCTION",
	"PING", "ECHO", "AUTH", "HELLO", "SELECT", "INFO", "CONFIG", "CLIENT", "COMMAND", "DBSIZE", "FLUSHDB", "FLUSHALL",
	"SAVE", "BGSAVE", "SLAVEOF", "REPLICAOF", "PSYNC", "SYNC", "REPLCONF", "WAIT", "CLUSTER", "READONLY", "QUIT", "SETBIT", "GETBIT", "BITCOUNT", "PFADD", "PFCOUNT", "GEOADD",
)

// redisErrors bounds the error-code label: the leading uppercase word of an
// error reply.
var redisErrors = set(
	"ERR", "WRONGTYPE", "NOAUTH", "WRONGPASS", "NOPERM", "MOVED", "ASK", "BUSY", "BUSYGROUP", "LOADING", "OOM",
	"READONLY", "EXECABORT", "CLUSTERDOWN", "TRYAGAIN", "MASTERDOWN", "NOSCRIPT", "NOREPLICAS", "CROSSSLOT", "UNKILLABLE",
)

func parseRedis(toServer bool, d []byte) (Obs, bool) {
	if !toServer {
		return parseRedisReply(d)
	}
	// Array of bulk strings: *<n>\r\n$<len>\r\n<COMMAND>\r\n ...
	if d[0] == '*' {
		nl := bytes.Index(d, []byte("\r\n"))
		if nl < 2 || nl > 12 || !allDigits(d[1:nl]) {
			return Obs{}, false
		}
		rest := d[nl+2:]
		if len(rest) < 4 || rest[0] != '$' {
			return Obs{}, false
		}
		nl2 := bytes.Index(rest, []byte("\r\n"))
		if nl2 < 2 || nl2 > 8 || !allDigits(rest[1:nl2]) {
			return Obs{}, false
		}
		cmd, _ := upperWord(rest[nl2+2:], 32)
		if cmd == "" {
			return Obs{}, false
		}
		return Obs{Proto: ProtoRedis, Kind: KindRequest, Op: pick(redisCommands, cmd)}, true
	}
	// Inline command: a bare word then CRLF (what telnet or a health check sends).
	w, whole := upperWord(d, 32)
	nl := bytes.IndexByte(d, '\n')
	if w == "" || !whole || nl < 0 {
		return Obs{}, false
	}
	// "GET / HTTP/1.1" is a valid inline GET with the key "/", and an HTTP request
	// that reached a Redis port is far more likely than a Redis client sending it.
	if bytes.Contains(d[:nl], []byte(" HTTP/")) {
		return Obs{}, false
	}
	if _, known := redisCommands[w]; !known {
		return Obs{}, false // an unknown bare word is too likely not Redis to count
	}
	return Obs{Proto: ProtoRedis, Kind: KindRequest, Op: w}, true
}

func parseRedisReply(d []byte) (Obs, bool) {
	switch d[0] {
	case '+':
		return Obs{Proto: ProtoRedis, Kind: KindResponse, Status: StatusOK}, true
	case ':', '$', '*', '_', '#', ',', '%', '~', '>', '=', '(', '|':
		return Obs{Proto: ProtoRedis, Kind: KindResponse, Status: StatusOK}, true
	case '-':
		w, _ := upperWord(d[1:], 24)
		if w == "" {
			return Obs{}, false
		}
		code := "other"
		if _, ok := redisErrors[w]; ok {
			code = w
		}
		return Obs{Proto: ProtoRedis, Kind: KindResponse, Status: StatusError, Code: code}, true
	}
	return Obs{}, false
}

func allDigits(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
