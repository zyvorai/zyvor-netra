// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import "time"

// Func adapts a function to a Collector. The agent uses it to publish
// counters it already reads from its own eBPF maps, so those maps are read
// once per tick and never by a second reader.
type Func struct {
	Meta Info
	Fn   func(now time.Time, e *Emitter) error
}

func (f *Func) Info() Info { return f.Meta }

func (f *Func) Collect(now time.Time, e *Emitter) error {
	if f.Fn == nil {
		return nil
	}
	return f.Fn(now, e)
}
