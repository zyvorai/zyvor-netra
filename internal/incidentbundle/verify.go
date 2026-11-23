// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package incidentbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MaxFileBytes is the largest bundle file (or tar member) Verify will read.
const MaxFileBytes = 3 * MaxTotalBytes

// VerifyReport is the result of Verify. It fails closed: any problem makes OK false.
type VerifyReport struct {
	OK       bool     `json:"ok"`
	Schema   string   `json:"schema"`
	Sections int      `json:"sections"`
	Bytes    int      `json:"bytes"`
	Head     string   `json:"head,omitempty"`
	Problems []string `json:"problems"`
}

type verifier struct{ problems map[string]bool }

func (v *verifier) fail(format string, a ...any) {
	if len(v.problems) < 200 {
		v.problems[fmt.Sprintf(format, a...)] = true
	}
}

// VerifyFile accepts a bundle as raw JSON or as the tar.gz form and verifies it.
func VerifyFile(data []byte) VerifyReport {
	doc, pre, err := Load(data)
	if err != nil {
		return VerifyReport{Problems: []string{err.Error()}}
	}
	rep := Verify(doc)
	rep.Problems = append(pre, rep.Problems...)
	rep.OK = len(rep.Problems) == 0
	return rep
}

// Verify checks a bundle JSON document: schema version, window and size
// bounds, per-section strict field allow-list, forbidden payload-looking
// keys, secret-looking strings, the hash chain and timeline references.
func Verify(data []byte) VerifyReport {
	v := &verifier{problems: map[string]bool{}}
	rep := VerifyReport{Problems: []string{}}
	if len(data) > MaxFileBytes {
		v.fail("file is %d bytes, over the %d byte read limit", len(data), MaxFileBytes)
		return v.finish(rep)
	}
	var doc Bundle
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		v.fail("not a valid bundle document: %v", err)
		return v.finish(rep)
	}
	if dec.More() {
		v.fail("trailing data after the bundle document")
	}
	rep.Schema = doc.Schema
	if doc.Schema != Schema {
		v.fail("schema is %q, want %q", doc.Schema, Schema)
		return v.finish(rep)
	}
	start, e1 := time.Parse(time.RFC3339, doc.Window.Start)
	end, e2 := time.Parse(time.RFC3339, doc.Window.End)
	switch {
	case e1 != nil || e2 != nil:
		v.fail("window start or end is not an RFC 3339 time")
	case !end.After(start):
		v.fail("window end is not after start")
	case end.Sub(start) > MaxWindow:
		v.fail("window is %s, over the %s maximum", end.Sub(start), MaxWindow)
	case int(end.Sub(start)/time.Minute) != doc.Window.Minutes:
		v.fail("window minutes (%d) does not match start and end", doc.Window.Minutes)
	}
	if doc.Bounds.MaxTotalBytes <= 0 || doc.Bounds.MaxTotalBytes > MaxTotalBytes {
		v.fail("bounds.maxTotalBytes %d is outside 1..%d", doc.Bounds.MaxTotalBytes, MaxTotalBytes)
	}
	if doc.Identity.Product != "netra" {
		v.fail("identity.product is %q", doc.Identity.Product)
	}
	for _, s := range []string{doc.Identity.Version, doc.Identity.Node, doc.Identity.Mode, doc.GeneratedAt} {
		v.scan("identity", s)
	}
	mask := doc.Redaction.MaskIPs
	if mask != string(MaskNone) && mask != string(MaskIPs) && mask != string(MaskPrefix) {
		v.fail("redaction.maskIps is %q", mask)
	}

	total := 0
	trees := map[string]any{}
	for name := range doc.Sections {
		if !ValidSection(name) {
			v.fail("unknown section %q", name)
		}
	}
	for _, name := range SectionNames {
		raw, ok := doc.Sections[name]
		if !ok {
			v.fail("section %q is missing", name)
			continue
		}
		rep.Sections++
		c, err := canon(raw)
		if err != nil {
			v.fail("section %s is not valid JSON: %v", name, err)
			continue
		}
		total += len(c)
		sdec := json.NewDecoder(bytes.NewReader(raw))
		sdec.DisallowUnknownFields()
		typed := sectionTypes[name]()
		if err := sdec.Decode(typed); err != nil {
			v.fail("section %s has a field outside the allow-list or a bad type: %v", name, err)
			continue
		}
		tree, _ := decodeTree(raw)
		trees[name] = tree
		v.walk(name, tree, 0)
		if m, ok := tree.(map[string]any); ok {
			for list, lim := range listLimits {
				if arr, ok := m[list].([]any); ok && len(arr) > lim {
					v.fail("section %s list %s has %d rows, over the %d bound", name, list, len(arr), lim)
				}
			}
			for k, x := range m {
				if arr, ok := x.([]any); ok {
					if _, known := listLimits[k]; !known {
						v.fail("section %s has an unbounded list %q", name, k)
					} else if len(arr) > maxListAny {
						v.fail("section %s list %s exceeds %d rows", name, k, maxListAny)
					}
				}
			}
			if name == SecMetrics {
				if ss, ok := m["series"].([]any); ok {
					for _, s := range ss {
						if sm, ok := s.(map[string]any); ok {
							if vals, ok := sm["values"].([]any); ok && len(vals) > MaxPoints {
								v.fail("a metric series has %d points, over the %d bound", len(vals), MaxPoints)
							}
						}
					}
				}
			}
			ex, _ := m["excluded"].(bool)
			if ex != contains(doc.Redaction.ExcludedSections, name) {
				v.fail("section %s excluded flag disagrees with redaction.excludedSections", name)
			}
		}
	}
	rep.Bytes = total
	if total > MaxTotalBytes || (doc.Bounds.MaxTotalBytes > 0 && total > doc.Bounds.MaxTotalBytes) {
		v.fail("sections are %d bytes, over the total size bound", total)
	}
	if doc.Bounds.Bytes != total {
		v.fail("bounds.bytes (%d) does not match the sections (%d)", doc.Bounds.Bytes, total)
	}

	want := chain(&doc)
	rep.Head = doc.Integrity.Head
	if doc.Integrity.Algorithm != "sha256" {
		v.fail("integrity.algorithm is %q", doc.Integrity.Algorithm)
	}
	if doc.Integrity.Seed != want.Seed {
		v.fail("integrity seed mismatch: the window, identity or redaction block was changed")
	}
	if len(doc.Integrity.Chain) != len(want.Chain) {
		v.fail("integrity chain has %d links, want %d", len(doc.Integrity.Chain), len(want.Chain))
	} else {
		for i, l := range doc.Integrity.Chain {
			w := want.Chain[i]
			if l.Section != w.Section || l.SHA256 != w.SHA256 || l.Chain != w.Chain || l.Bytes != w.Bytes {
				v.fail("integrity mismatch at section %s: its content was changed", w.Section)
			}
		}
	}
	if doc.Integrity.Head != want.Head {
		v.fail("integrity head mismatch")
	}

	v.refs(trees)
	if mask == string(MaskIPs) {
		for name, t := range trees {
			v.unmasked(name, t)
		}
	}
	return v.finish(rep)
}

func (v *verifier) finish(rep VerifyReport) VerifyReport {
	for p := range v.problems {
		rep.Problems = append(rep.Problems, p)
	}
	sort.Strings(rep.Problems)
	rep.OK = len(rep.Problems) == 0
	return rep
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (v *verifier) scan(where, s string) {
	for _, p := range scanString(s) {
		v.fail("%s: %s", where, p)
	}
}

func (v *verifier) walk(path string, t any, depth int) {
	if depth > 12 {
		v.fail("%s: nesting deeper than 12", path)
		return
	}
	switch x := t.(type) {
	case string:
		v.scan(path, x)
	case []any:
		for _, e := range x {
			v.walk(path, e, depth+1)
		}
	case map[string]any:
		for k, e := range x {
			if forbiddenKey(k) {
				v.fail("%s: field %q is payload- or credential-shaped and is never allowed", path, k)
			}
			v.scan(path+" key", k)
			v.walk(path+"."+k, e, depth+1)
		}
	}
}

// unmasked finds an IP address in a bundle that claims its addresses were
// replaced with pseudonyms.
func (v *verifier) unmasked(path string, t any) {
	switch x := t.(type) {
	case string:
		for _, tok := range append(ipv4Re.FindAllString(x, -1), ipv6Re.FindAllString(x, -1)...) {
			if i := strings.IndexByte(tok, '/'); i >= 0 {
				tok = tok[:i]
			}
			if a, err := netip.ParseAddr(tok); err == nil && !a.IsUnspecified() {
				v.fail("%s: contains an unmasked IP address although maskIps is on", path)
				return
			}
		}
	case []any:
		for _, e := range x {
			v.unmasked(path, e)
		}
	case map[string]any:
		for _, e := range x {
			v.unmasked(path, e)
		}
	}
}

// refs checks that every timeline ref points at a row that exists.
func (v *verifier) refs(trees map[string]any) {
	tl, _ := trees[SecTimeline].(map[string]any)
	entries, _ := tl["entries"].([]any)
	for _, e := range entries {
		em, _ := e.(map[string]any)
		ref, _ := em["ref"].(string)
		parts := strings.Split(ref, "/")
		if len(parts) != 3 {
			v.fail("timeline ref %q is malformed", ref)
			continue
		}
		sec, _ := trees[parts[0]].(map[string]any)
		list, _ := sec[parts[1]].([]any)
		idx, err := strconv.Atoi(parts[2])
		if sec == nil || err != nil || idx < 0 || idx >= len(list) {
			v.fail("timeline ref %q points at nothing", ref)
		}
	}
}

// ---- tar.gz ----

// Manifest lists every member of the tar.gz form with its sha256.
type Manifest struct {
	Schema string         `json:"schema"`
	Bundle string         `json:"bundleHead"`
	Files  []ManifestFile `json:"files"`
}

// ManifestFile is one member.
type ManifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

const manifestSchema = "netra-incident-bundle-manifest/1"

// WriteTarGz packs a bundle as bundle.json, one canonical file per section and
// manifest.json holding the sha256 of every other member. The archive is
// deterministic for a given bundle.
func WriteTarGz(bundle []byte) ([]byte, error) {
	var doc Bundle
	if err := json.Unmarshal(bundle, &doc); err != nil {
		return nil, err
	}
	pretty := &bytes.Buffer{}
	if err := json.Indent(pretty, bundle, "", "  "); err != nil {
		return nil, err
	}
	pretty.WriteByte('\n')
	files := map[string][]byte{"bundle.json": pretty.Bytes()}
	for name, raw := range doc.Sections {
		c, err := canon(raw)
		if err != nil {
			return nil, err
		}
		files["sections/"+name+".json"] = append(c, '\n')
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	man := Manifest{Schema: manifestSchema, Bundle: doc.Integrity.Head}
	for _, n := range names {
		man.Files = append(man.Files, ManifestFile{Name: n, SHA256: sum(files[n]), Bytes: len(files[n])})
	}
	mj, _ := json.MarshalIndent(man, "", "  ")
	files["manifest.json"] = append(mj, '\n')
	order := append([]string{"manifest.json"}, names...)
	mod, _ := time.Parse(time.RFC3339, doc.GeneratedAt)

	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	tw := tar.NewWriter(gz)
	for _, n := range order {
		b := files[n]
		if err := tw.WriteHeader(&tar.Header{Name: "netra-incident-bundle/" + n, Mode: 0o644, Size: int64(len(b)), ModTime: mod, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Load returns the bundle JSON from either form. For a tar.gz it also checks
// the manifest and returns what it found wrong as problems.
func Load(data []byte) (bundle []byte, problems []string, err error) {
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return loadTar(data)
	}
	return data, nil, nil
}

func loadTar(data []byte) ([]byte, []string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, nil, fmt.Errorf("not a readable gzip file: %w", err)
	}
	tr := tar.NewReader(io.LimitReader(gz, 4*MaxFileBytes))
	members := map[string][]byte{}
	var problems []string
	for n := 0; ; n++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("bad tar: %w", err)
		}
		if n >= 64 {
			return nil, nil, fmt.Errorf("more than 64 members")
		}
		if h.Typeflag != tar.TypeReg {
			problems = append(problems, "archive member "+h.Name+" is not a regular file")
			continue
		}
		name := strings.TrimPrefix(h.Name, "netra-incident-bundle/")
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
			problems = append(problems, "archive member "+h.Name+" has an unsafe path")
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, MaxFileBytes+1))
		if err != nil || len(b) > MaxFileBytes {
			return nil, nil, fmt.Errorf("member %s is unreadable or over %d bytes", h.Name, MaxFileBytes)
		}
		members[name] = b
	}
	mb, ok := members["manifest.json"]
	if !ok {
		return nil, nil, fmt.Errorf("archive has no manifest.json")
	}
	var man Manifest
	if err := json.Unmarshal(mb, &man); err != nil || man.Schema != manifestSchema {
		return nil, nil, fmt.Errorf("manifest.json is not a %s manifest", manifestSchema)
	}
	seen := map[string]bool{"manifest.json": true}
	for _, f := range man.Files {
		seen[f.Name] = true
		b, ok := members[f.Name]
		switch {
		case !ok:
			problems = append(problems, "manifest lists "+f.Name+" but it is missing from the archive")
		case sum(b) != f.SHA256 || len(b) != f.Bytes:
			problems = append(problems, "archive member "+f.Name+" does not match its manifest sha256")
		}
	}
	for n := range members {
		if !seen[n] {
			problems = append(problems, "archive member "+n+" is not listed in the manifest")
		}
	}
	bundle, ok := members["bundle.json"]
	if !ok {
		return nil, nil, fmt.Errorf("archive has no bundle.json")
	}
	// Each section file must be the canonical form of the section in bundle.json.
	var doc Bundle
	if err := json.Unmarshal(bundle, &doc); err == nil {
		for name, raw := range doc.Sections {
			c, _ := canon(raw)
			if f, ok := members["sections/"+name+".json"]; !ok || !bytes.Equal(bytes.TrimSpace(f), c) {
				problems = append(problems, "sections/"+name+".json differs from the section in bundle.json")
			}
		}
	}
	sort.Strings(problems)
	return bundle, problems, nil
}
