// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7sample

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func mustParse(t *testing.T, p Protocol, toServer bool, data []byte) Obs {
	t.Helper()
	o, ok := Parse(p, toServer, data)
	if !ok {
		t.Fatalf("%s toServer=%v: not classified: %q", p, toServer, data)
	}
	return o
}

func mustNot(t *testing.T, p Protocol, toServer bool, data []byte) {
	t.Helper()
	if o, ok := Parse(p, toServer, data); ok {
		t.Fatalf("%s toServer=%v: %q classified as %+v, want not classified", p, toServer, data, o)
	}
}

// ---- Redis ----

func TestRedisRequests(t *testing.T) {
	for in, want := range map[string]string{
		"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n":       "SET",
		"*2\r\n$3\r\nget\r\n$1\r\nk\r\n":                        "GET",
		"*1\r\n$4\r\nPING\r\n":                                  "PING",
		"*4\r\n$4\r\nHSET\r\n$1\r\nh\r\n$1\r\nf\r\n$1\r\nv\r\n": "HSET",
		"*1\r\n$7\r\nFOOBARX\r\n":                               "OTHER",
		"PING\r\n":                                              "PING",
	} {
		o := mustParse(t, ProtoRedis, true, []byte(in))
		if o.Kind != KindRequest || o.Op != want {
			t.Errorf("%q => %+v, want request %s", in, o, want)
		}
	}
	for _, in := range []string{"greetings friend\r\n", "*x\r\n", "*2\r\nfoo\r\n", "\x00\x01\x02", "*1\r\n$4\r\n\r\n", "GET / HTTP/1.1\r\n"} {
		mustNot(t, ProtoRedis, true, []byte(in))
	}
}

func TestRedisReplies(t *testing.T) {
	for in, want := range map[string]struct {
		st   Status
		code string
	}{
		"+OK\r\n":                                {StatusOK, ""},
		":1000\r\n":                              {StatusOK, ""},
		"$3\r\nfoo\r\n":                          {StatusOK, ""},
		"*2\r\n$1\r\na\r\n$1\r\nb\r\n":           {StatusOK, ""},
		"-ERR unknown command 'x'\r\n":           {StatusError, "ERR"},
		"-WRONGTYPE Operation against a key\r\n": {StatusError, "WRONGTYPE"},
		"-NOAUTH Authentication required.\r\n":   {StatusError, "NOAUTH"},
		"-MYSTERIOUS whatever\r\n":               {StatusError, "other"},
	} {
		o := mustParse(t, ProtoRedis, false, []byte(in))
		if o.Kind != KindResponse || o.Status != want.st || o.Code != want.code {
			t.Errorf("%q => %+v, want %v/%q", in, o, want.st, want.code)
		}
	}
	mustNot(t, ProtoRedis, false, []byte("Xnothing"))
	mustNot(t, ProtoRedis, false, []byte("-\r\n"))
}

// ---- PostgreSQL ----

func pgMsg(typ byte, body []byte) []byte {
	b := []byte{typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(4+len(body)))
	return append(b, body...)
}

func TestPostgresFrontend(t *testing.T) {
	startup := make([]byte, 8)
	binary.BigEndian.PutUint32(startup[0:], 40)
	binary.BigEndian.PutUint32(startup[4:], 196608)
	startup = append(startup, []byte("user\x00alice\x00database\x00db\x00\x00")...)
	ssl := []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}

	for name, c := range map[string]struct {
		in   []byte
		want string
	}{
		"startup":       {startup, "startup"},
		"ssl request":   {ssl, "ssl_request"},
		"select":        {pgMsg('Q', []byte("SELECT * FROM users WHERE id = 1\x00")), "SELECT"},
		"lowercase":     {pgMsg('Q', []byte("insert into t values (1)\x00")), "INSERT"},
		"leading space": {pgMsg('Q', []byte("   \n update t set a=1\x00")), "UPDATE"},
		"block comment": {pgMsg('Q', []byte("/* trace=abc */ DELETE FROM t\x00")), "DELETE"},
		"line comment":  {pgMsg('Q', []byte("-- who\nSELECT 1\x00")), "SELECT"},
		"unknown verb":  {pgMsg('Q', []byte("FROBNICATE things\x00")), "OTHER"},
		"parse":         {pgMsg('P', []byte("stmt1\x00SELECT $1\x00\x00\x00")), "SELECT"},
		"bind":          {pgMsg('B', []byte("\x00\x00\x00\x00\x00")), "bind"},
		"terminate":     {pgMsg('X', nil), "terminate"},
		"password":      {pgMsg('p', []byte("hunter2\x00")), "auth"},
	} {
		o := mustParse(t, ProtoPostgres, true, c.in)
		if o.Kind != KindRequest || o.Op != c.want {
			t.Errorf("%s => %+v, want %s", name, o, c.want)
		}
	}
	mustNot(t, ProtoPostgres, true, []byte("GET / HTTP/1.1\r\n\r\n"))
	mustNot(t, ProtoPostgres, true, []byte{'Q', 0, 0, 0, 1, 'x'}) // length below the minimum
}

func TestPostgresBackend(t *testing.T) {
	errBody := []byte("SERROR\x00C42P01\x00Mrelation \"secret_table\" does not exist\x00\x00")
	for name, c := range map[string]struct {
		in   []byte
		want Obs
	}{
		"error":    {pgMsg('E', errBody), Obs{Kind: KindResponse, Status: StatusError, Code: "42"}},
		"select":   {pgMsg('C', []byte("SELECT 5\x00")), Obs{Kind: KindResponse, Op: "SELECT", Status: StatusOK}},
		"insert":   {pgMsg('C', []byte("INSERT 0 1\x00")), Obs{Kind: KindResponse, Op: "INSERT", Status: StatusOK}},
		"ready":    {pgMsg('Z', []byte("I")), Obs{Kind: KindResponse, Op: "ready", Status: StatusOK}},
		"auth ok":  {pgMsg('R', []byte{0, 0, 0, 0}), Obs{Kind: KindResponse, Op: "auth", Status: StatusOK}},
		"auth req": {pgMsg('R', []byte{0, 0, 0, 5, 1, 2, 3, 4}), Obs{Kind: KindResponse, Op: "auth"}},
		"row":      {pgMsg('D', []byte{0, 1}), Obs{Kind: KindResponse, Status: StatusOK}},
	} {
		o := mustParse(t, ProtoPostgres, false, c.in)
		c.want.Proto = ProtoPostgres
		if o != c.want {
			t.Errorf("%s => %+v, want %+v", name, o, c.want)
		}
	}
	// A message without a SQLSTATE still classifies, with a bounded code.
	if o := mustParse(t, ProtoPostgres, false, pgMsg('E', []byte("SERROR\x00Mboom\x00\x00"))); o.Code != "other" {
		t.Errorf("no SQLSTATE => %q, want other", o.Code)
	}
	mustNot(t, ProtoPostgres, false, []byte("HTTP/1.1 200 OK"))
}

// ---- MySQL ----

func myPkt(seq byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, payload...)
}

func TestMySQL(t *testing.T) {
	for name, c := range map[string]struct {
		toServer bool
		in       []byte
		want     Obs
	}{
		"query":    {true, myPkt(0, append([]byte{0x03}, "SELECT 1"...)), Obs{Kind: KindRequest, Op: "SELECT"}},
		"insert":   {true, myPkt(0, append([]byte{0x03}, "  insert into t values (1)"...)), Obs{Kind: KindRequest, Op: "INSERT"}},
		"ping":     {true, myPkt(0, []byte{0x0e}), Obs{Kind: KindRequest, Op: "ping"}},
		"prepare":  {true, myPkt(0, append([]byte{0x16}, "SELECT ?"...)), Obs{Kind: KindRequest, Op: "stmt_prepare"}},
		"ok":       {false, myPkt(1, []byte{0, 0, 0, 2, 0, 0, 0}), Obs{Kind: KindResponse, Status: StatusOK}},
		"err auth": {false, myPkt(1, append([]byte{0xff, 0x15, 0x04, '#'}, "28000Access denied"...)), Obs{Kind: KindResponse, Status: StatusError, Code: "access_denied"}},
		"err dup":  {false, myPkt(1, append([]byte{0xff, 0x26, 0x04, '#'}, "23000Duplicate"...)), Obs{Kind: KindResponse, Status: StatusError, Code: "constraint"}},
		"err odd":  {false, myPkt(1, []byte{0xff, 0x01, 0x09, '#', 'x'}), Obs{Kind: KindResponse, Status: StatusError, Code: "other"}},
		"eof":      {false, myPkt(2, []byte{0xfe, 0, 0, 2, 0}), Obs{Kind: KindResponse, Status: StatusOK}},
		"greeting": {false, myPkt(0, append([]byte{0x0a}, "8.0.32\x00"...)), Obs{Kind: KindResponse, Op: "handshake"}},
	} {
		o := mustParse(t, ProtoMySQL, c.toServer, c.in)
		c.want.Proto = ProtoMySQL
		if o != c.want {
			t.Errorf("%s => %+v, want %+v", name, o, c.want)
		}
	}
	mustNot(t, ProtoMySQL, true, myPkt(1, []byte{0x03, 'x'})) // not a command packet
	mustNot(t, ProtoMySQL, true, []byte{0, 0, 0, 0, 3})       // empty payload
}

// ---- Kafka ----

func kafkaReq(key, ver uint16) []byte {
	b := make([]byte, 0, 24)
	b = binary.BigEndian.AppendUint32(b, 20)
	b = binary.BigEndian.AppendUint16(b, key)
	b = binary.BigEndian.AppendUint16(b, ver)
	b = binary.BigEndian.AppendUint32(b, 7)
	return append(b, 0xff, 0xff, 0, 0, 0, 0, 0, 0)
}

func TestKafka(t *testing.T) {
	for key, want := range map[uint16]string{0: "Produce", 1: "Fetch", 3: "Metadata", 18: "ApiVersions", 11: "JoinGroup", 70: "Other"} {
		o := mustParse(t, ProtoKafka, true, kafkaReq(key, 3))
		if o.Kind != KindRequest || o.Op != want {
			t.Errorf("api key %d => %+v, want %s", key, o, want)
		}
	}
	mustNot(t, ProtoKafka, true, kafkaReq(99, 3))                            // impossible api key
	mustNot(t, ProtoKafka, true, kafkaReq(0, 99))                            // impossible version
	mustNot(t, ProtoKafka, false, kafkaReq(0, 3))                            // responses are not classifiable statelessly
	mustNot(t, ProtoKafka, true, []byte{0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0}) // size below a header
}

// ---- HTTP/1 ----

func TestHTTP1(t *testing.T) {
	o := mustParse(t, ProtoHTTP1, true, []byte("GET /orders/42?token=SECRET-TOKEN HTTP/1.1\r\nHost: Shop.Example.COM:8443\r\nCookie: session=SECRET-COOKIE\r\n\r\n"))
	if o.Kind != KindRequest || o.Op != "GET" || o.Host != "shop.example.com" {
		t.Fatalf("request = %+v", o)
	}
	for _, in := range []string{"POST /x HTTP/1.1\r\n\r\n", "DELETE /x HTTP/1.0\r\n\r\n"} {
		mustParse(t, ProtoHTTP1, true, []byte(in))
	}
	if o := mustParse(t, ProtoHTTP1, true, []byte("GET / HTTP/1.1\r\nHost: bad host!\r\n\r\n")); o.Host != "" {
		t.Errorf("an invalid Host must be dropped, got %q", o.Host)
	}
	for in, want := range map[string]Obs{
		"HTTP/1.1 200 OK\r\n":              {Kind: KindResponse, Status: StatusOK, Code: "200"},
		"HTTP/1.1 404 Not Found\r\n":       {Kind: KindResponse, Status: StatusError, Code: "404"},
		"HTTP/1.0 503 Service Unavail\r\n": {Kind: KindResponse, Status: StatusError, Code: "503"},
	} {
		want.Proto = ProtoHTTP1
		if got := mustParse(t, ProtoHTTP1, false, []byte(in)); got != want {
			t.Errorf("%q => %+v, want %+v", in, got, want)
		}
	}
	for _, in := range []string{"FOO /x HTTP/1.1\r\n", "GET / HTTP/2\r\n", "HTTP/1.1 999 X\r\n", "GET", "\x16\x03\x01"} {
		mustNot(t, ProtoHTTP1, true, []byte(in))
	}
}

// ---- HTTP/2 and gRPC ----

func h2Frame(typ, flags byte, stream uint32, payload []byte) []byte {
	f := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(f[5:], stream)
	return append(f, payload...)
}

func hpackBlock(enc *hpack.Encoder, buf *bytes.Buffer, fields ...[2]string) []byte {
	buf.Reset()
	for _, f := range fields {
		_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	return append([]byte(nil), buf.Bytes()...)
}

func newEnc() (*hpack.Encoder, *bytes.Buffer) {
	var b bytes.Buffer
	return hpack.NewEncoder(&b), &b
}

func grpcReqFields(path string) [][2]string {
	return [][2]string{{":method", "POST"}, {":scheme", "http"}, {":path", path}, {":authority", "greeter.svc.local:50051"}, {"content-type", "application/grpc"}, {"te", "trailers"}, {"authorization", "Bearer SECRET-BEARER"}}
}

func TestHTTP2GRPCRequest(t *testing.T) {
	enc, buf := newEnc()
	block := hpackBlock(enc, buf, grpcReqFields("/helloworld.Greeter/SayHello")...)
	sample := append([]byte(h2Preface), h2Frame(0x4, 0, 0, nil)...) // SETTINGS
	sample = append(sample, h2Frame(0x1, 0x4, 1, block)...)         // HEADERS, END_HEADERS
	o := mustParse(t, ProtoHTTP2, true, sample)
	if o.Kind != KindRequest || o.Op != "/helloworld.Greeter/SayHello" || !o.GRPC || o.Host != "greeter.svc.local" {
		t.Fatalf("gRPC request = %+v", o)
	}
}

func TestHTTP2PathIsOnlyUsedAsALabelWhenItLooksLikeAGRPCMethod(t *testing.T) {
	enc, buf := newEnc()
	for path, want := range map[string]string{"/a b/c": "grpc", "/no-slash-method": "grpc", "/x/y?token=SECRET": "grpc"} {
		o := mustParse(t, ProtoHTTP2, true, h2Frame(0x1, 0x4, 1, hpackBlock(enc, buf, grpcReqFields(path)...)))
		_ = want
		if o.Op != "grpc" || strings.Contains(fmt.Sprint(o), "SECRET") {
			t.Errorf("path %q => %+v", path, o)
		}
		enc, buf = newEnc() // fresh dynamic table each time
	}
}

func TestHTTP2PlainRequestNeverExposesThePath(t *testing.T) {
	enc, buf := newEnc()
	block := hpackBlock(enc, buf, [2]string{":method", "GET"}, [2]string{":scheme", "https"}, [2]string{":path", "/admin/users/SECRET-ID?key=SECRET-KEY"}, [2]string{":authority", "api.example.com"})
	o := mustParse(t, ProtoHTTP2, true, h2Frame(0x1, 0x4, 1, block))
	if o.Op != "GET" || o.GRPC || o.Host != "api.example.com" || strings.Contains(fmt.Sprintf("%+v", o), "SECRET") {
		t.Fatalf("plain h2 request = %+v", o)
	}
}

func TestHTTP2Responses(t *testing.T) {
	for name, c := range map[string]struct {
		fields [][2]string
		want   Obs
		ok     bool
	}{
		"200":           {[][2]string{{":status", "200"}}, Obs{Kind: KindResponse, Status: StatusOK, Code: "200"}, true},
		"503":           {[][2]string{{":status", "503"}}, Obs{Kind: KindResponse, Status: StatusError, Code: "503"}, true},
		"grpc ok":       {[][2]string{{"grpc-status", "0"}}, Obs{Kind: KindResponse, Status: StatusOK, Code: "grpc_0", GRPC: true}, true},
		"grpc unavail":  {[][2]string{{"grpc-status", "14"}, {"grpc-message", "connection refused SECRET"}}, Obs{Kind: KindResponse, Status: StatusError, Code: "grpc_14", GRPC: true}, true},
		"trailers only": {[][2]string{{":status", "200"}, {"content-type", "application/grpc"}, {"grpc-status", "12"}}, Obs{Kind: KindResponse, Status: StatusError, Code: "grpc_12", GRPC: true}, true},
		"grpc initial":  {[][2]string{{":status", "200"}, {"content-type", "application/grpc"}}, Obs{}, false},
		"bad grpc":      {[][2]string{{"grpc-status", "99"}}, Obs{}, false},
	} {
		enc, buf := newEnc()
		o, ok := Parse(ProtoHTTP2, false, h2Frame(0x1, 0x4, 1, hpackBlock(enc, buf, c.fields...)))
		c.want.Proto = ProtoHTTP2
		if ok != c.ok || (ok && o != c.want) {
			t.Errorf("%s => %+v ok=%v, want %+v ok=%v", name, o, ok, c.want, c.ok)
		}
	}
}

func TestHTTP2UndecodableWhenHPACKStateIsMissing(t *testing.T) {
	// The second request on a connection references dynamic-table entries the
	// first one created. A sample that misses the first cannot decode it, and must
	// say so rather than guess.
	enc, buf := newEnc()
	_ = hpackBlock(enc, buf, grpcReqFields("/pkg.Svc/First")...)
	second := hpackBlock(enc, buf, grpcReqFields("/pkg.Svc/First")...)
	o := mustParse(t, ProtoHTTP2, true, h2Frame(0x1, 0x4, 3, second))
	if o.Op != "undecodable_headers" {
		t.Fatalf("second request = %+v, want undecodable_headers", o)
	}
	// A truncated HEADERS frame is also undecodable, not an error.
	enc2, buf2 := newEnc()
	full := h2Frame(0x1, 0x4, 1, hpackBlock(enc2, buf2, grpcReqFields("/pkg.Svc/M")...))
	if o := mustParse(t, ProtoHTTP2, true, full[:len(full)-6]); o.Op != "undecodable_headers" {
		t.Fatalf("truncated = %+v", o)
	}
}

func TestHTTP2ConnectionPrefaceAndNonClassifiableFrames(t *testing.T) {
	if o := mustParse(t, ProtoHTTP2, true, []byte(h2Preface)); o.Op != "connection" {
		t.Fatalf("preface = %+v", o)
	}
	mustNot(t, ProtoHTTP2, true, h2Frame(0x0, 0, 1, []byte("some data frame body"))) // DATA
	mustNot(t, ProtoHTTP2, true, h2Frame(0x8, 0, 0, []byte{0, 0, 0xff, 0xff}))       // WINDOW_UPDATE
	mustNot(t, ProtoHTTP2, false, append([]byte(h2Preface), 0, 0, 0))                // a preface never flows to the client
	// Padding and priority fields are skipped, not misread as header bytes.
	enc, buf := newEnc()
	block := hpackBlock(enc, buf, grpcReqFields("/p.S/M")...)
	padded := append([]byte{3}, block...)
	padded = append(padded, 0, 0, 0)
	if o := mustParse(t, ProtoHTTP2, true, h2Frame(0x1, 0x4|0x8, 1, padded)); o.Op != "/p.S/M" {
		t.Fatalf("padded HEADERS = %+v", o)
	}
}

// ---- properties across every parser ----

var (
	hostRE = regexp.MustCompile(`^[a-z0-9._\-\[\]:]{1,255}$`)
	codeRE = regexp.MustCompile(`^[A-Za-z0-9_]{0,24}$`)
)

// allowedOps is everything an Op may legitimately be, for the bounded-label check.
func allowedOp(o Obs) bool {
	switch o.Op {
	case "", "OTHER", "Other", "grpc", "connection", "undecodable_headers":
		return true
	}
	if _, ok := redisCommands[o.Op]; ok {
		return true
	}
	if _, ok := sqlVerbs[o.Op]; ok {
		return true
	}
	if _, ok := httpMethods[o.Op]; ok {
		return true
	}
	for _, n := range kafkaAPIs {
		if n == o.Op && n != "" {
			return true
		}
	}
	switch o.Op {
	case "startup", "ssl_request", "gss_request", "cancel", "parse", "bind", "execute", "describe", "close", "sync", "flush",
		"terminate", "function_call", "auth", "copy_data", "ready", "quit", "init_db", "field_list", "ping", "stmt_prepare",
		"stmt_execute", "stmt_close", "set_option", "handshake":
		return true
	}
	return grpcPath.MatchString(o.Op)
}

func labelsBounded(o Obs) error {
	if !allowedOp(o) {
		return fmt.Errorf("op %q is not an allowlisted or validated label", o.Op)
	}
	if !codeRE.MatchString(o.Code) {
		return fmt.Errorf("code %q is not a bounded token", o.Code)
	}
	if o.Host != "" && !hostRE.MatchString(o.Host) {
		return fmt.Errorf("host %q is not a hostname", o.Host)
	}
	return nil
}

func TestRandomInputNeverPanicsAndOnlyEverYieldsBoundedLabels(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	enc, buf := newEnc()
	seeds := [][]byte{
		[]byte("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n"), []byte("-ERR x\r\n"), pgMsg('Q', []byte("SELECT 1\x00")), pgMsg('E', []byte("SERROR\x00C42P01\x00\x00")),
		myPkt(0, []byte{0x03, 'S', 'E', 'L'}), kafkaReq(3, 1), []byte("GET / HTTP/1.1\r\nHost: a.b\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n"),
		append([]byte(h2Preface), h2Frame(0x1, 0x4, 1, hpackBlock(enc, buf, grpcReqFields("/a.B/c")...))...),
	}
	for i := 0; i < 200000; i++ {
		var d []byte
		if r.Intn(3) == 0 { // pure noise
			d = make([]byte, r.Intn(300))
			r.Read(d)
		} else { // a valid message with bytes flipped or cut
			d = append([]byte(nil), seeds[r.Intn(len(seeds))]...)
			for k := r.Intn(4); k > 0 && len(d) > 0; k-- {
				d[r.Intn(len(d))] = byte(r.Intn(256))
			}
			if len(d) > 0 && r.Intn(3) == 0 {
				d = d[:r.Intn(len(d))]
			}
		}
		p := Protocol(1 + r.Intn(int(protoCount)-1))
		toServer := r.Intn(2) == 0
		if o, ok := Parse(p, toServer, d); ok {
			if err := labelsBounded(o); err != nil {
				t.Fatalf("%s toServer=%v input %q: %v", p, toServer, d, err)
			}
		}
	}
}

// Secrets in keys, SQL, topics, paths, cookies and bearer tokens must never reach
// an Obs, whatever the protocol.
func TestSecretsNeverAppearInAnyOutputField(t *testing.T) {
	const secret = "TOPSECRET-9f8e7d"
	enc, buf := newEnc()
	h2 := h2Frame(0x1, 0x4, 1, hpackBlock(enc, buf,
		[2]string{":method", "POST"}, [2]string{":path", "/pkg.Svc/" + secret}, [2]string{":authority", "h.example"},
		[2]string{"content-type", "application/grpc"}, [2]string{"authorization", "Bearer " + secret}))
	msgs := map[Protocol][][]byte{
		ProtoRedis: {[]byte("*3\r\n$3\r\nSET\r\n$" + fmt.Sprint(len(secret)) + "\r\n" + secret + "\r\n$1\r\nv\r\n"), []byte("-ERR " + secret + "\r\n"), []byte("GET " + secret + "\r\n")},
		ProtoPostgres: {pgMsg('Q', []byte("SELECT '"+secret+"' FROM users\x00")), pgMsg('E', []byte("SERROR\x00C42501\x00M"+secret+"\x00\x00")),
			pgMsg('E', []byte("SERROR\x00M"+secret+"\x00C42501\x00D"+secret+"\x00\x00")), // message before the code
			pgMsg('p', []byte(secret+"\x00")), pgMsg('C', []byte("SELECT 1 "+secret+"\x00"))},
		ProtoMySQL: {myPkt(0, append([]byte{0x03}, ("SELECT '"+secret+"'")...)), myPkt(1, append([]byte{0xff, 0x15, 0x04, '#'}, ("28000"+secret)...))},
		ProtoKafka: {append(kafkaReq(0, 3), []byte(secret)...)},
		ProtoHTTP1: {[]byte("GET /" + secret + "?k=" + secret + " HTTP/1.1\r\nHost: h.example\r\nCookie: " + secret + "\r\nAuthorization: Bearer " + secret + "\r\n\r\n")},
		ProtoHTTP2: {h2},
	}
	for p, list := range msgs {
		for _, m := range list {
			for _, toServer := range []bool{true, false} {
				if o, ok := Parse(p, toServer, m); ok {
					if s := fmt.Sprintf("%+v", o); strings.Contains(strings.ToLower(s), strings.ToLower(secret)) {
						t.Errorf("%s toServer=%v leaked the secret: %s (input %q)", p, toServer, s, m)
					}
				}
			}
		}
	}
}

func TestParseEdgeCases(t *testing.T) {
	if _, ok := Parse(ProtoRedis, true, nil); ok {
		t.Error("empty input classified")
	}
	if _, ok := Parse(ProtoUnknown, true, []byte("x")); ok {
		t.Error("unknown protocol classified")
	}
	if ProtocolByName("grpc") != ProtoHTTP2 || ProtocolByName("redis") != ProtoRedis || ProtocolByName("nope") != ProtoUnknown {
		t.Error("ProtocolByName")
	}
	if ProtoHTTP2.String() != "http2" || KindResponse.String() != "response" || StatusError.String() != "error" {
		t.Error("String methods")
	}
}

// FuzzParse feeds arbitrary bytes to every parser in both directions. The only
// properties are the two that matter for a component that reads untrusted network
// payloads: it must never panic, and anything it does classify must use only
// bounded labels. `go test` runs the seed corpus; CI also fuzzes it for a while.
func FuzzParse(f *testing.F) {
	enc, buf := newEnc()
	for _, s := range [][]byte{
		[]byte("*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n"), []byte("-ERR x\r\n"), []byte("PING\r\n"),
		pgMsg('Q', []byte("SELECT 1\x00")), pgMsg('E', []byte("SERROR\x00C42P01\x00Mx\x00\x00")), pgMsg('C', []byte("INSERT 0 1\x00")),
		myPkt(0, append([]byte{0x03}, "SELECT 1"...)), myPkt(1, []byte{0xff, 0x15, 0x04, '#', 'x'}), kafkaReq(3, 1),
		[]byte("GET / HTTP/1.1\r\nHost: a.b\r\n\r\n"), []byte("HTTP/1.1 404 Not Found\r\n"),
		append([]byte(h2Preface), h2Frame(0x1, 0x4, 1, hpackBlock(enc, buf, grpcReqFields("/a.B/c")...))...),
	} {
		f.Add(uint8(1), true, s)
		f.Add(uint8(3), false, s)
	}
	f.Fuzz(func(t *testing.T, proto uint8, toServer bool, data []byte) {
		p := Protocol(proto % uint8(protoCount))
		o, ok := Parse(p, toServer, data)
		if !ok {
			return
		}
		if err := labelsBounded(o); err != nil {
			t.Fatalf("%s toServer=%v %q: %v", p, toServer, data, err)
		}
	})
}
