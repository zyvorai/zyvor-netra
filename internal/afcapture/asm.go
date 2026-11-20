// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package afcapture

import (
	"fmt"

	"golang.org/x/net/bpf"
)

// label is an opaque forward-jump target used while building a classic-BPF
// (cBPF) program. Classic BPF instructions encode jumps as a forward-only
// skip count computed relative to the jumping instruction itself, which is
// error-prone to hand-count for anything beyond a trivial filter. asmBuilder
// is a small two-pass assembler: build() records label positions in pass
// one, then resolves every recorded jump into the raw skip-count form
// golang.org/x/net/bpf expects in pass two. Label 0 is reserved to mean
// "fall through" (skip 0), so real labels start at 1.
type label int

const fallthroughLabel label = 0

type asmBuilder struct {
	items []asmItem
	next  label
}

type asmItem struct {
	isLabel bool
	lbl     label
	plain   bpf.Instruction
	jumpIf  *jumpIfLabeled
	jump    *jumpLabeled
}

type jumpIfLabeled struct {
	cond            bpf.JumpTest
	val             uint32
	onTrue, onFalse label
}

type jumpLabeled struct {
	target label
}

func newAsm() *asmBuilder { return &asmBuilder{} }

// newLabel allocates a fresh label with no position yet — mark it later at
// the instruction it should point to.
func (b *asmBuilder) newLabel() label {
	b.next++
	return b.next
}

// mark records that lbl refers to the next instruction emitted after this
// call (a label with nothing emitted after it, i.e. at the very end of the
// program, is also valid — it resolves to len(instructions)).
func (b *asmBuilder) mark(l label) {
	b.items = append(b.items, asmItem{isLabel: true, lbl: l})
}

func (b *asmBuilder) emit(i bpf.Instruction) {
	b.items = append(b.items, asmItem{plain: i})
}

// jumpIfTo emits a conditional jump: if A <cond> val, jump to onTrue,
// otherwise jump to onFalse. Either may be fallthroughLabel to mean
// "continue to the next instruction" for that branch.
func (b *asmBuilder) jumpIfTo(cond bpf.JumpTest, val uint32, onTrue, onFalse label) {
	b.items = append(b.items, asmItem{jumpIf: &jumpIfLabeled{cond, val, onTrue, onFalse}})
}

// jumpTo emits an unconditional jump to target.
func (b *asmBuilder) jumpTo(target label) {
	b.items = append(b.items, asmItem{jump: &jumpLabeled{target}})
}

// assemble resolves every label reference and returns the finished
// instruction list, ready for bpf.Assemble.
func (b *asmBuilder) assemble() ([]bpf.Instruction, error) {
	pos := map[label]int{}
	idx := 0
	for _, it := range b.items {
		if it.isLabel {
			pos[it.lbl] = idx
			continue
		}
		idx++
	}
	// A label marked at the very end of the program (no instruction after
	// it) resolves to the final instruction count — record that too.
	pos[fallthroughLabel] = -1 // never resolved through the map; skip=0 always

	out := make([]bpf.Instruction, 0, idx)
	idx = 0
	skipTo := func(target label) (int, error) {
		if target == fallthroughLabel {
			return 0, nil
		}
		p, ok := pos[target]
		if !ok {
			return 0, fmt.Errorf("afcapture: unresolved label %d", target)
		}
		d := p - (idx + 1)
		if d < 0 {
			return 0, fmt.Errorf("afcapture: backward jump not supported (label %d)", target)
		}
		return d, nil
	}
	for _, it := range b.items {
		if it.isLabel {
			continue
		}
		switch {
		case it.jumpIf != nil:
			jt, err := skipTo(it.jumpIf.onTrue)
			if err != nil {
				return nil, err
			}
			jf, err := skipTo(it.jumpIf.onFalse)
			if err != nil {
				return nil, err
			}
			if jt > 255 || jf > 255 {
				return nil, fmt.Errorf("afcapture: conditional jump out of range (jt=%d jf=%d)", jt, jf)
			}
			out = append(out, bpf.JumpIf{Cond: it.jumpIf.cond, Val: it.jumpIf.val, SkipTrue: uint8(jt), SkipFalse: uint8(jf)})
		case it.jump != nil:
			d, err := skipTo(it.jump.target)
			if err != nil {
				return nil, err
			}
			out = append(out, bpf.Jump{Skip: uint32(d)})
		default:
			out = append(out, it.plain)
		}
		idx++
	}
	return out, nil
}
