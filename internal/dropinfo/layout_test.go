// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package dropinfo

import (
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/zyvorai/netra/internal/tpformat"
)

func fixture(t *testing.T, text string) *tpformat.Format {
	t.Helper()
	f, err := tpformat.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func real68(t *testing.T) *tpformat.Format {
	t.Helper()
	b, err := os.ReadFile("../tpformat/testdata/linux-6.8-kfree_skb.format")
	if err != nil {
		t.Fatal(err)
	}
	return fixture(t, string(b))
}

func TestLayoutSizeMatchesTheCStruct(t *testing.T) {
	// struct dropinfo_layout in bpf/netra_dropinfo.c is 4×u16 + 2×u8 = 10 bytes.
	if got := unsafe.Sizeof(Layout{}); got != 10 {
		t.Fatalf("Layout is %d bytes, the C struct is 10", got)
	}
}

func TestRealKernelLayout(t *testing.T) {
	l, err := LayoutFor(real68(t))
	if err != nil {
		t.Fatal(err)
	}
	want := Layout{SkbAddr: 8, Location: 16, Protocol: 24, Reason: 28, Valid: 1}
	if l != want {
		t.Fatalf("got %+v, want %+v", l, want)
	}
}

const preReasonKernel = `name: kfree_skb
format:
	field:void * skbaddr;	offset:8;	size:8;	signed:0;
	field:void * location;	offset:16;	size:8;	signed:0;
	field:unsigned short protocol;	offset:24;	size:2;	signed:0;
print fmt: "skbaddr=%p protocol=%u location=%p", REC->skbaddr, REC->protocol, REC->location
`

func TestKernelWithoutReasonStillWorksAndMarksItAbsent(t *testing.T) {
	f := fixture(t, preReasonKernel)
	l, err := LayoutFor(f)
	if err != nil {
		t.Fatal(err)
	}
	if l.Reason != Absent || l.Location != 16 || l.Valid != 1 {
		t.Fatalf("got %+v", l)
	}
	if ReasonNames(f) != nil {
		t.Error("a kernel without a reason table should have no names")
	}
	if got := ReasonName(nil, 0); got != "unknown" {
		t.Errorf("reason on a pre-reason kernel = %q, want unknown", got)
	}
}

func TestLayoutRefusesWhatItCannotReadSafely(t *testing.T) {
	for name, text := range map[string]string{
		"no skbaddr":       strings.ReplaceAll(preReasonKernel, "skbaddr;", "skbptr;"),
		"no protocol":      strings.ReplaceAll(preReasonKernel, "unsigned short protocol", "unsigned short proto"),
		"skbaddr 4 bytes":  strings.Replace(preReasonKernel, "offset:8;	size:8", "offset:8;	size:4", 1),
		"protocol 4 bytes": strings.Replace(preReasonKernel, "offset:24;	size:2", "offset:24;	size:4", 1),
	} {
		if _, err := LayoutFor(fixture(t, text)); err == nil {
			t.Errorf("%s: LayoutFor should have failed", name)
		}
	}
}

func TestOptionalFieldsOfTheWrongSizeAreAbsentNotMisread(t *testing.T) {
	text := strings.Replace(preReasonKernel, "offset:16;	size:8", "offset:16;	size:4", 1)
	l, err := LayoutFor(fixture(t, text))
	if err != nil {
		t.Fatal(err)
	}
	if l.Location != Absent {
		t.Errorf("a 4-byte location must be Absent, got offset %d", l.Location)
	}
}

func TestReasonNamesComeFromTheKernelAndFallBackStably(t *testing.T) {
	names := ReasonNames(real68(t))
	for v, want := range map[uint32]string{2: "NOT_SPECIFIED", 3: "NO_SOCKET", 8: "NETFILTER_DROP"} {
		if got := ReasonName(names, v); got != want {
			t.Errorf("reason %d = %q, want %q", v, got, want)
		}
	}
	// A subsystem-qualified reason (high bits set) is not in the core table.
	if got := ReasonName(names, 1<<16|3); got != "reason_65539" {
		t.Errorf("got %q", got)
	}
}
