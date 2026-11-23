// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package incidentbundle

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

// DiffSchema identifies a diff document.
const DiffSchema = "netra-incident-diff/1"

const maxSamples = 8

// Side summarises one input of a diff.
type Side struct {
	GeneratedAt string `json:"generatedAt"`
	WindowStart string `json:"windowStart"`
	WindowEnd   string `json:"windowEnd"`
	Version     string `json:"version"`
	Mode        string `json:"mode"`
	Scope       string `json:"scope"`
	Node        string `json:"node,omitempty"`
	MaskIPs     string `json:"maskIps"`
	MaskKeyID   string `json:"maskKeyId,omitempty"`
	Head        string `json:"head"`
}

// FieldChange is a scalar that differs.
type FieldChange struct {
	Path string `json:"path"`
	A    string `json:"a"`
	B    string `json:"b"`
}

// ItemChange is a row present on both sides whose numbers differ.
type ItemChange struct {
	Item   string        `json:"item"`
	Fields []FieldChange `json:"fields"`
}

// ListDiff compares one list of one section.
type ListDiff struct {
	List    string       `json:"list"`
	CountA  int          `json:"countA"`
	CountB  int          `json:"countB"`
	Added   []string     `json:"added,omitempty"`
	Removed []string     `json:"removed,omitempty"`
	Changed []ItemChange `json:"changed,omitempty"`
	// Totals are the full counts; the slices above keep the first few.
	AddedTotal   int `json:"addedTotal"`
	RemovedTotal int `json:"removedTotal"`
	ChangedTotal int `json:"changedTotal"`
}

// SectionDiff compares one section.
type SectionDiff struct {
	Section   string        `json:"section"`
	Identical bool          `json:"identical"`
	Fields    []FieldChange `json:"fields,omitempty"`
	Lists     []ListDiff    `json:"lists,omitempty"`
}

// DiffReport is deterministic for two given bundles.
type DiffReport struct {
	Schema     string        `json:"schema"`
	A          Side          `json:"a"`
	B          Side          `json:"b"`
	SameWindow bool          `json:"sameWindow"`
	Notes      []string      `json:"notes"`
	Identity   []FieldChange `json:"identity,omitempty"`
	Sections   []SectionDiff `json:"sections"`
	Identical  bool          `json:"identical"`
	Summary    string        `json:"summary"`
}

func side(d *Bundle) Side {
	return Side{GeneratedAt: d.GeneratedAt, WindowStart: d.Window.Start, WindowEnd: d.Window.End, Version: d.Identity.Version, Mode: d.Identity.Mode,
		Scope: d.Identity.Scope, Node: d.Identity.Node, MaskIPs: d.Redaction.MaskIPs, MaskKeyID: d.Redaction.MaskKeyID, Head: d.Integrity.Head}
}

// ignoredFields vary run to run without meaning anything.
var ignoredFields = map[string]bool{"firstSeen": true, "lastSeen": true, "since": true, "startUnix": true, "ageSeconds": true, "observedAt": true}

// Diff compares two bundles section by section. Rows are matched on their
// non-numeric fields; matched rows whose numbers differ are "changed".
func Diff(a, b []byte) (*DiffReport, error) {
	var da, db Bundle
	if err := json.Unmarshal(a, &da); err != nil {
		return nil, fmt.Errorf("first bundle: %w", err)
	}
	if err := json.Unmarshal(b, &db); err != nil {
		return nil, fmt.Errorf("second bundle: %w", err)
	}
	if da.Schema != Schema || db.Schema != Schema {
		return nil, fmt.Errorf("both inputs must be %s", Schema)
	}
	rep := &DiffReport{Schema: DiffSchema, A: side(&da), B: side(&db), Notes: []string{}, Sections: []SectionDiff{}}
	rep.SameWindow = da.Window.Minutes == db.Window.Minutes
	if !rep.SameWindow {
		rep.Notes = append(rep.Notes, fmt.Sprintf("windows differ in length (%d and %d minutes): counts are not directly comparable", da.Window.Minutes, db.Window.Minutes))
	}
	if da.Redaction.MaskIPs != db.Redaction.MaskIPs || da.Redaction.MaskKeyID != db.Redaction.MaskKeyID {
		rep.Notes = append(rep.Notes, "the bundles were masked differently (mode or key): IP-derived values will not match and appear as added and removed")
	}
	rep.Identity = scalarDiff("identity", mustTree(da.Identity), mustTree(db.Identity))
	allSame := len(rep.Identity) == 0
	for _, name := range SectionNames {
		ta, _ := decodeTree(da.Sections[name])
		tb, _ := decodeTree(db.Sections[name])
		sd := SectionDiff{Section: name, Identical: true}
		ma, _ := ta.(map[string]any)
		mb, _ := tb.(map[string]any)
		keys := map[string]bool{}
		for k := range ma {
			keys[k] = true
		}
		for k := range mb {
			keys[k] = true
		}
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			la, aok := ma[k].([]any)
			lb, bok := mb[k].([]any)
			if aok || bok {
				if k == "truncated" {
					continue
				}
				ld := diffList(name, k, la, lb)
				if ld.AddedTotal+ld.RemovedTotal+ld.ChangedTotal > 0 {
					sd.Lists = append(sd.Lists, ld)
					sd.Identical = false
				}
				continue
			}
			sd.Fields = append(sd.Fields, scalarDiff(k, ma[k], mb[k])...)
		}
		if len(sd.Fields) > 0 {
			sd.Identical = false
		}
		if !sd.Identical {
			allSame = false
		}
		rep.Sections = append(rep.Sections, sd)
	}
	rep.Identical = allSame
	changed := 0
	for _, s := range rep.Sections {
		if !s.Identical {
			changed++
		}
	}
	rep.Summary = fmt.Sprintf("%d of %d sections differ", changed, len(rep.Sections))
	if rep.Identical {
		rep.Summary = "the bundles hold the same recorded content"
	}
	return rep, nil
}

func mustTree(v any) any {
	raw, _ := json.Marshal(v)
	t, _ := decodeTree(raw)
	return t
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return fmt.Sprint(t)
	}
	raw, _ := json.Marshal(v)
	return string(raw)
}

func scalarDiff(prefix string, a, b any) []FieldChange {
	var out []FieldChange
	ma, aMap := a.(map[string]any)
	mb, bMap := b.(map[string]any)
	if aMap || bMap {
		keys := map[string]bool{}
		for k := range ma {
			keys[k] = true
		}
		for k := range mb {
			keys[k] = true
		}
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if ignoredFields[k] {
				continue
			}
			out = append(out, scalarDiff(prefix+"."+k, ma[k], mb[k])...)
		}
		return out
	}
	if str(a) != str(b) {
		out = append(out, FieldChange{Path: prefix, A: str(a), B: str(b)})
	}
	return out
}

type row struct {
	identity string
	nums     map[string]float64
	label    string
}

func toRow(v any) row {
	m, ok := v.(map[string]any)
	if !ok {
		s := str(v)
		return row{identity: s, label: clip(s)}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	r := row{nums: map[string]float64{}}
	var id []string
	for _, k := range keys {
		if ignoredFields[k] {
			continue
		}
		switch t := m[k].(type) {
		case json.Number:
			f, _ := t.Float64()
			r.nums[k] = f
		case []any:
			if allNumbers(t) {
				continue
			}
			id = append(id, k+"="+str(t))
		case nil:
		default:
			id = append(id, k+"="+str(t))
		}
	}
	r.identity = strings.Join(id, "|")
	r.label = clip(r.identity)
	return r
}

func allNumbers(l []any) bool {
	for _, e := range l {
		switch e.(type) {
		case json.Number, nil:
		default:
			return false
		}
	}
	return true
}

func clip(s string) string {
	if len(s) > 140 {
		return s[:140] + "..."
	}
	return s
}

func diffList(section, list string, la, lb []any) ListDiff {
	ld := ListDiff{List: list, CountA: len(la), CountB: len(lb)}
	index := func(l []any) (map[string][]row, []string) {
		m := map[string][]row{}
		var order []string
		for _, e := range l {
			r := toRow(e)
			if _, ok := m[r.identity]; !ok {
				order = append(order, r.identity)
			}
			m[r.identity] = append(m[r.identity], r)
		}
		sort.Strings(order)
		return m, order
	}
	ia, oa := index(la)
	ib, ob := index(lb)
	for _, id := range oa {
		ra := ia[id]
		rb, ok := ib[id]
		if !ok {
			ld.RemovedTotal += len(ra)
			for _, r := range ra {
				if len(ld.Removed) < maxSamples {
					ld.Removed = append(ld.Removed, r.label)
				}
			}
			continue
		}
		if len(ra) > len(rb) {
			ld.RemovedTotal += len(ra) - len(rb)
			if len(ld.Removed) < maxSamples {
				ld.Removed = append(ld.Removed, ra[0].label)
			}
		}
		n := len(ra)
		if len(rb) < n {
			n = len(rb)
		}
		for i := 0; i < n; i++ {
			var fc []FieldChange
			keys := map[string]bool{}
			for k := range ra[i].nums {
				keys[k] = true
			}
			for k := range rb[i].nums {
				keys[k] = true
			}
			names := make([]string, 0, len(keys))
			for k := range keys {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				x, y := ra[i].nums[k], rb[i].nums[k]
				if x != y && !(math.IsNaN(x) && math.IsNaN(y)) {
					fc = append(fc, FieldChange{Path: k, A: fmt.Sprint(x), B: fmt.Sprint(y)})
				}
			}
			if len(fc) > 0 {
				ld.ChangedTotal++
				if len(ld.Changed) < maxSamples {
					ld.Changed = append(ld.Changed, ItemChange{Item: ra[i].label, Fields: fc})
				}
			}
		}
	}
	for _, id := range ob {
		rb := ib[id]
		ra, ok := ia[id]
		if !ok {
			ld.AddedTotal += len(rb)
			for _, r := range rb {
				if len(ld.Added) < maxSamples {
					ld.Added = append(ld.Added, r.label)
				}
			}
			continue
		}
		if len(rb) > len(ra) {
			ld.AddedTotal += len(rb) - len(ra)
			if len(ld.Added) < maxSamples {
				ld.Added = append(ld.Added, rb[0].label)
			}
		}
	}
	return ld
}
