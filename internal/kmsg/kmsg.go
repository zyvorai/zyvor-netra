// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package kmsg keeps a bounded, scrubbed view of kernel log lines.
// It does not read the application journal.
package kmsg

import (
	"strings"
	"unicode/utf8"
)

// Note is one kept line.
type Note struct {
	Text string `json:"text"`
}

// Filter keeps network and OOM lines and drops anything that looks like
// a credential. max caps the result, newest last in input order, keeping
// the tail.
func Filter(blob string, max int) []Note {
	if max <= 0 {
		max = 20
	}
	var kept []Note
	for _, line := range strings.Split(blob, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !interesting(line) || secretLike(line) {
			continue
		}
		if len(line) > 180 {
			cut := 180
			for cut > 0 && !utf8.RuneStart(line[cut]) {
				cut--
			}
			line = line[:cut]
		}
		kept = append(kept, Note{Text: line})
	}
	if len(kept) > max {
		kept = kept[len(kept)-max:]
	}
	return kept
}

func interesting(line string) bool {
	l := strings.ToLower(line)
	for _, w := range []string{"netdev", "tcp:", "udp:", "nf_conntrack", "out of memory", "killed process", "oom-kill"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

func secretLike(line string) bool {
	l := strings.ToLower(line)
	for _, w := range []string{"password", "secret", "token", "bearer", "authorization"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}
