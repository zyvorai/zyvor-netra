// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package tpformat

import (
	"os"
	"strings"
	"testing"
)

func load(t *testing.T, name string) *Format {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(string(b))
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return f
}

func off(t *testing.T, f *Format, name string, size int) int {
	t.Helper()
	o, err := f.Offset(name, size)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// Captured from a real Linux 6.8.0 x86_64 kernel (the live host). The two
// reset tracepoints are siblings yet lay out their tuple differently, which is
// the reason this package exists.
func TestRealKernelSiblingTracepointsHaveDifferentLayouts(t *testing.T) {
	send, recv := load(t, "linux-6.8-tcp_send_reset.format"), load(t, "linux-6.8-tcp_receive_reset.format")
	if send.Name != "tcp_send_reset" || recv.Name != "tcp_receive_reset" {
		t.Fatalf("names = %q, %q", send.Name, recv.Name)
	}
	if got := off(t, send, "sport", 2); got != 28 {
		t.Fatalf("tcp_send_reset sport = %d, want 28", got)
	}
	if got := off(t, recv, "sport", 2); got != 16 {
		t.Fatalf("tcp_receive_reset sport = %d, want 16", got)
	}
	if send.Has("sock_cookie") || !recv.Has("sock_cookie") {
		t.Fatal("sock_cookie exists only on tcp_receive_reset")
	}
	if !send.Has("state") || recv.Has("state") {
		t.Fatal("state exists only on tcp_send_reset")
	}
}

func TestRetransmitAndStateChangeLayouts(t *testing.T) {
	r := load(t, "linux-6.8-tcp_retransmit_skb.format")
	for name, want := range map[string]int{"skbaddr": 8, "skaddr": 16, "state": 24, "sport": 28, "dport": 30, "family": 32, "saddr": 34, "daddr": 38, "saddr_v6": 42, "daddr_v6": 58} {
		if got, err := r.Offset(name, 0); err != nil || got != want {
			t.Errorf("tcp_retransmit_skb %s = %d (%v), want %d", name, got, err, want)
		}
	}
	s := load(t, "linux-6.8-inet_sock_set_state.format")
	for name, want := range map[string]int{"oldstate": 16, "newstate": 20, "sport": 24, "dport": 26, "family": 28, "protocol": 30, "saddr": 32, "daddr": 36, "saddr_v6": 40, "daddr_v6": 56} {
		if got, err := s.Offset(name, 0); err != nil || got != want {
			t.Errorf("inet_sock_set_state %s = %d (%v), want %d", name, got, err, want)
		}
	}
}

func TestArrayAndPointerFieldsAreParsedByName(t *testing.T) {
	f := load(t, "linux-6.8-tcp_retransmit_skb.format")
	saddr := f.Fields["saddr"]
	if saddr.ArrayLen != 4 || saddr.Size != 4 || saddr.Type != "__u8" {
		t.Fatalf("saddr = %+v", saddr)
	}
	if v6 := f.Fields["saddr_v6"]; v6.ArrayLen != 16 || v6.Size != 16 {
		t.Fatalf("saddr_v6 = %+v", v6)
	}
	if p := f.Fields["skbaddr"]; p.Name != "skbaddr" || p.Size != 8 || !strings.Contains(p.Type, "void") {
		t.Fatalf("skbaddr = %+v (the `const void *` declaration must yield the name skbaddr)", p)
	}
	if c := f.Fields["common_type"]; c.Name != "common_type" || c.Type != "unsigned short" {
		t.Fatalf("common_type = %+v", c)
	}
	if st := f.Fields["state"]; !st.Signed {
		t.Fatal("state is a signed int")
	}
}

func TestOffsetRejectsMissingAndWrongSizedFields(t *testing.T) {
	f := load(t, "linux-6.8-tcp_receive_reset.format")
	if _, err := f.Offset("state", 4); err == nil || !strings.Contains(err.Error(), "no field") {
		t.Fatalf("missing field err = %v", err)
	}
	if _, err := f.Offset("sport", 4); err == nil || !strings.Contains(err.Error(), "expected 4") {
		t.Fatalf("a 2-byte field read as 4 bytes must be refused, got %v", err)
	}
	if o, err := f.Offset("sport", 2); err != nil || o != 16 {
		t.Fatalf("sport = %d, %v", o, err)
	}
}

func TestDynamicDataLocFieldsParse(t *testing.T) {
	f, err := Parse("name: x\nformat:\n\tfield:__data_loc char[] msg;\toffset:8;\tsize:4;\tsigned:0;\n")
	if err != nil {
		t.Fatal(err)
	}
	if fld := f.Fields["msg"]; fld.Offset != 8 || fld.Size != 4 {
		t.Fatalf("msg = %+v", fld)
	}
}

func TestParseRejectsInputThatWouldYieldAWrongOffset(t *testing.T) {
	cases := map[string]string{
		"not a format":           "hello world\n",
		"empty":                  "",
		"field without offset":   "name: x\n\tfield:int a;\tsize:4;\tsigned:0;\n",
		"field without size":     "name: x\n\tfield:int a;\toffset:4;\tsigned:0;\n",
		"non-numeric offset":     "name: x\n\tfield:int a;\toffset:four;\tsize:4;\tsigned:0;\n",
		"negative offset":        "name: x\n\tfield:int a;\toffset:-4;\tsize:4;\tsigned:0;\n",
		"absurd offset":          "name: x\n\tfield:int a;\toffset:99999999;\tsize:4;\tsigned:0;\n",
		"offset plus size wraps": "name: x\n\tfield:int a;\toffset:65534;\tsize:65535;\tsigned:0;\n",
		"empty declaration":      "name: x\n\tfield:;\toffset:0;\tsize:4;\tsigned:0;\n",
		"unterminated array":     "name: x\n\tfield:__u8 a[4;\toffset:0;\tsize:4;\tsigned:0;\n",
		"duplicate field name":   "name: x\n\tfield:int a;\toffset:0;\tsize:4;\tsigned:0;\n\tfield:int a;\toffset:4;\tsize:4;\tsigned:0;\n",
		"truncated field line":   "name: x\n\tfield:int a;\n",
	}
	for name, text := range cases {
		if _, err := Parse(text); err == nil {
			t.Errorf("%s: Parse should fail rather than yield a bogus offset", name)
		}
	}
}

func TestNonFieldLinesAreIgnored(t *testing.T) {
	f, err := Parse("name: y\nID: 42\nformat:\n\tfield:int a;\toffset:8;\tsize:4;\tsigned:1;\n\nprint fmt: \"a=%d\", REC->a\n")
	if err != nil || f.Name != "y" || len(f.Fields) != 1 {
		t.Fatalf("f = %+v, err = %v", f, err)
	}
}

func TestReadFailsCleanlyWhenTracefsIsAbsent(t *testing.T) {
	if _, err := Read("nonexistent", "nothing"); err == nil {
		t.Fatal("Read of a missing tracepoint must fail")
	}
}

func TestKfreeSkbReasonNamesComeFromTheKernelsOwnTable(t *testing.T) {
	f := load(t, "linux-6.8-kfree_skb.format")
	if got := off(t, f, "skbaddr", 8); got != 8 {
		t.Errorf("skbaddr offset = %d, want 8", got)
	}
	if got := off(t, f, "location", 8); got != 16 {
		t.Errorf("location offset = %d, want 16", got)
	}
	if got := off(t, f, "protocol", 2); got != 24 {
		t.Errorf("protocol offset = %d, want 24", got)
	}
	if got := off(t, f, "reason", 4); got != 28 {
		t.Errorf("reason offset = %d, want 28", got)
	}
	sym := f.Symbols("reason")
	for v, want := range map[int]string{2: "NOT_SPECIFIED", 3: "NO_SOCKET", 8: "NETFILTER_DROP", 35: "TCP_RESET", 95: "MAX"} {
		if sym[v] != want {
			t.Errorf("reason %d = %q, want %q", v, sym[v], want)
		}
	}
	if len(sym) < 90 {
		t.Errorf("only %d reasons parsed from a 6.8 format file", len(sym))
	}
	if f.Symbols("protocol") != nil {
		t.Error("a field with no __print_symbolic should have no table")
	}
}

func TestSymbolTablesHandleHexAndSeveralFields(t *testing.T) {
	f, err := Parse("name: x\nformat:\n\tfield:int a;\toffset:8;\tsize:4;\tsigned:1;\n\tfield:int b;\toffset:12;\tsize:4;\tsigned:1;\n" +
		"print fmt: \"%s %s\", __print_symbolic(REC->a, { 0x1, \"ONE\" }, { 2, \"TWO\" }), __print_symbolic(REC->b, { 7, \"SEVEN\" })\n")
	if err != nil {
		t.Fatal(err)
	}
	if a := f.Symbols("a"); a[1] != "ONE" || a[2] != "TWO" || len(a) != 2 {
		t.Errorf("a = %v", a)
	}
	if b := f.Symbols("b"); b[7] != "SEVEN" || len(b) != 1 {
		t.Errorf("b = %v", b)
	}
}

func TestMalformedSymbolTableIsIgnoredNotFatal(t *testing.T) {
	f, err := Parse("name: x\nformat:\n\tfield:int a;\toffset:8;\tsize:4;\tsigned:1;\nprint fmt: \"%s\", __print_symbolic(REC->a, { oops })\n")
	if err != nil {
		t.Fatal(err)
	}
	if f.Symbols("a") != nil {
		t.Error("a malformed table should yield no names")
	}
}

// Linux 6.17, captured from a GitHub Actions runner. tcp_send_reset changed
// shape between 6.8 and 6.17, which is the reason layouts are read from the
// running kernel rather than assumed.
func TestLinux617FormatsParseAndTcpSendResetChangedShape(t *testing.T) {
	for _, n := range []string{"tcp_retransmit_skb", "tcp_send_reset", "tcp_receive_reset", "inet_sock_set_state", "kfree_skb"} {
		load(t, "linux-6.17-"+n+".format")
	}
	f := load(t, "linux-6.17-tcp_send_reset.format")
	if f.Has("sport") || f.Has("family") {
		t.Error("6.17 tcp_send_reset should have no classic sport/family fields")
	}
	for _, name := range []string{"saddr", "daddr"} {
		if fld := f.Fields[name]; fld.Size != 28 || fld.ArrayLen != 28 {
			t.Errorf("%s = %+v, want a 28-byte array", name, fld)
		}
	}
	if o, _ := f.Offset("saddr", 28); o != 32 {
		t.Errorf("saddr offset = %d, want 32", o)
	}
	if o, _ := f.Offset("daddr", 28); o != 60 {
		t.Errorf("daddr offset = %d, want 60", o)
	}
	old := load(t, "linux-6.8-tcp_send_reset.format")
	if !old.Has("sport") {
		t.Error("6.8 tcp_send_reset should still have the classic fields")
	}
}

func TestLinux617KfreeSkbReasonNamesAndLayout(t *testing.T) {
	f := load(t, "linux-6.17-kfree_skb.format")
	if got := off(t, f, "skbaddr", 8); got != 8 {
		t.Errorf("skbaddr = %d", got)
	}
	sym := f.Symbols("reason")
	if sym[12] != "NETFILTER_DROP" || sym[3] != "NO_SOCKET" || sym[45] != "TCP_RESET" || sym[74] != "UNHANDLED_PROTO" {
		t.Errorf("reason names on 6.17: 12=%q 3=%q 45=%q 74=%q", sym[12], sym[3], sym[45], sym[74])
	}
	if len(sym) < 100 {
		t.Errorf("only %d reasons on 6.17; the table only grows", len(sym))
	}
}

// The drop-reason numbering is not stable across kernels: NETFILTER_DROP is 8 on
// 6.8 and 12 on 6.17, TCP_RESET 35 and 45, UNHANDLED_PROTO 56 and 74. A table of
// names baked into the agent would mislabel every drop on one of them; reading
// the running kernel's own table is what keeps the labels right. Both real
// tables are checked against the other's numbering here so that a "simplification"
// to a fixed table fails.
func TestDropReasonNumberingDiffersBetweenKernelsAndNamesFollowTheKernel(t *testing.T) {
	k68 := load(t, "linux-6.8-kfree_skb.format").Symbols("reason")
	k617 := load(t, "linux-6.17-kfree_skb.format").Symbols("reason")
	for name, nums := range map[string][2]int{"NETFILTER_DROP": {8, 12}, "TCP_RESET": {35, 45}, "UNHANDLED_PROTO": {56, 74}} {
		if k68[nums[0]] != name || k617[nums[1]] != name {
			t.Errorf("%s: 6.8[%d]=%q 6.17[%d]=%q", name, nums[0], k68[nums[0]], nums[1], k617[nums[1]])
		}
		if k68[nums[1]] == name || k617[nums[0]] == name {
			t.Errorf("%s resolves under the other kernel's number: the tables must not be interchangeable", name)
		}
	}
	// Stable across both, and so a safe anchor.
	if k68[3] != "NO_SOCKET" || k617[3] != "NO_SOCKET" {
		t.Error("NO_SOCKET is 3 on both")
	}
}
