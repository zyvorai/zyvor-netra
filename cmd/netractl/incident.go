// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/incidentbundle"
)

const incidentUsage = "usage: netractl incident bundle [--minutes N] [--node NAME] [--exclude SECTION,...] [--mask-ips[=prefix]] [--mask-key KEY] [--format json|tgz] [--out FILE]\n" +
	"       netractl incident verify FILE [--json] [--seal FILE.seal --key-file KEY]\n" +
	"       netractl incident seal FILE [--key-file KEY] [--out FILE.seal]\n" +
	"       netractl incident report FILE [--json] [--out FILE]\n" +
	"       netractl incident diff A B [--json]"

// incidentCmd is the incident flight recorder: bundle, verify, diff. Bundle
// reads GET /api/v1/incident/bundle; verify and diff are local and offline.
func incidentCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", incidentUsage)
	}
	switch args[0] {
	case "bundle":
		return incidentBundle(args[1:])
	case "verify":
		return incidentVerify(args[1:])
	case "diff":
		return incidentDiff(args[1:])
	case "seal":
		return incidentSeal(args[1:])
	case "report":
		return incidentReport(args[1:])
	}
	return fmt.Errorf("unknown incident command %q\n%s", args[0], incidentUsage)
}

func incidentBundle(args []string) error {
	q := url.Values{}
	out, format := "", ""
	headers := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		var v string
		switch {
		case a == "--minutes":
			if v, err = val(); err == nil {
				if n, e := strconv.Atoi(v); e != nil || n < 1 || n > 1440 {
					return fmt.Errorf("--minutes must be a whole number from 1 to 1440")
				}
				q.Set("minutes", v)
			}
		case a == "--node":
			if v, err = val(); err == nil {
				q.Set("node", v)
			}
		case a == "--exclude":
			if v, err = val(); err == nil {
				q.Set("exclude", v)
			}
		case a == "--mask-ips":
			q.Set("mask_ips", "ips")
		case strings.HasPrefix(a, "--mask-ips="):
			m := strings.TrimPrefix(a, "--mask-ips=")
			if _, ok := incidentbundle.ParseMask(m); !ok {
				return fmt.Errorf("--mask-ips takes ips or prefix")
			}
			q.Set("mask_ips", m)
		case a == "--mask-key":
			if v, err = val(); err == nil {
				if len(v) > 128 {
					return fmt.Errorf("--mask-key is limited to 128 bytes")
				}
				headers["X-Netra-Mask-Key"] = v
			}
		case a == "--out":
			out, err = val()
		case a == "--format":
			if format, err = val(); err == nil && format != "json" && format != "tgz" {
				return fmt.Errorf("--format must be json or tgz")
			}
		default:
			return fmt.Errorf("unknown incident bundle flag %s\n%s", a, incidentUsage)
		}
		if err != nil {
			return err
		}
	}
	if format == "" {
		format = "json"
		if l := strings.ToLower(out); strings.HasSuffix(l, ".tar.gz") || strings.HasSuffix(l, ".tgz") {
			format = "tgz"
		}
	}
	if format == "tgz" && out == "" {
		return fmt.Errorf("--format tgz needs --out FILE")
	}
	p := "/api/v1/incident/bundle"
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	body, status, err := doRequest("GET", p, nil, headers)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("%s: %s", http.StatusText(status), strings.TrimSpace(string(body)))
	}
	// Never write a file that would not pass the offline check.
	if rep := incidentbundle.Verify(body); !rep.OK {
		return fmt.Errorf("the controller returned a bundle that fails verification (%s); not written", firstProblem(rep))
	}
	if out == "" {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, body, "", "  "); err != nil {
			return err
		}
		fmt.Println(pretty.String())
		return nil
	}
	var data []byte
	if format == "tgz" {
		if data, err = incidentbundle.WriteTarGz(body); err != nil {
			return err
		}
	} else {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, body, "", "  "); err != nil {
			return err
		}
		pretty.WriteByte('\n')
		data = pretty.Bytes()
	}
	if err := writeFileAtomic(out, data); err != nil {
		return err
	}
	var doc incidentbundle.Bundle
	_ = json.Unmarshal(body, &doc)
	trunc := 0
	for _, raw := range doc.Sections {
		var m struct {
			Truncated []incidentbundle.Trunc `json:"truncated"`
		}
		_ = json.Unmarshal(raw, &m)
		trunc += len(m.Truncated)
	}
	fmt.Printf("wrote %s (%d bytes, %s)\n  schema  %s\n  window  %s .. %s (%d min)\n  head    %s\n  masked  ips=%s, excluded=%d, truncated lists=%d\n",
		out, len(data), format, doc.Schema, doc.Window.Start, doc.Window.End, doc.Window.Minutes, doc.Integrity.Head, doc.Redaction.MaskIPs, len(doc.Redaction.ExcludedSections), trunc)
	fmt.Println("  check it before sharing: netractl incident verify " + out)
	return nil
}

func firstProblem(rep incidentbundle.VerifyReport) string {
	if len(rep.Problems) == 0 {
		return "unknown"
	}
	return rep.Problems[0]
}

// writeFileAtomic writes next to the target and renames, mode 0600: a bundle
// is safe to share on purpose, but is still operational data.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".netra-bundle-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func readBundleFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > incidentbundle.MaxFileBytes {
		return nil, fmt.Errorf("%s is %d bytes, over the %d byte limit", path, st.Size(), incidentbundle.MaxFileBytes)
	}
	return os.ReadFile(path)
}

func incidentVerify(args []string) error {
	var sealFile, keyFile string
	var plain []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--seal" && i+1 < len(args):
			i++
			sealFile = args[i]
		case args[i] == "--key-file" && i+1 < len(args):
			i++
			keyFile = args[i]
		default:
			plain = append(plain, args[i])
		}
	}
	asJSON, files := splitJSONFlag(plain)
	if len(files) != 1 {
		return fmt.Errorf("usage: netractl incident verify FILE [--json] [--seal FILE.seal --key-file KEY]")
	}
	data, err := readBundleFile(files[0])
	if err != nil {
		return err
	}
	if sealFile != "" {
		key, err := sealKey(keyFile)
		if err != nil {
			return err
		}
		sj, err := os.ReadFile(sealFile)
		if err != nil {
			return err
		}
		if err := incidentbundle.VerifySeal(data, sj, key); err != nil {
			return fmt.Errorf("seal check failed: %w", err)
		}
		fmt.Printf("SEAL OK  %s matches %s\n", sealFile, files[0])
	}
	rep := incidentbundle.VerifyFile(data)
	if asJSON {
		x, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(x))
	} else if rep.OK {
		fmt.Printf("OK  %s  schema %s  %d sections  %d bytes\n    chain head %s\n", files[0], rep.Schema, rep.Sections, rep.Bytes, rep.Head)
	} else {
		fmt.Printf("FAIL  %s\n", files[0])
		for _, p := range rep.Problems {
			fmt.Println("  - " + p)
		}
	}
	if !rep.OK {
		return fmt.Errorf("bundle verification failed (%d problems)", len(rep.Problems))
	}
	return nil
}

func splitJSONFlag(args []string) (bool, []string) {
	var rest []string
	asJSON := false
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		} else {
			rest = append(rest, a)
		}
	}
	return asJSON, rest
}

func incidentDiff(args []string) error {
	asJSON, files := splitJSONFlag(args)
	if len(files) != 2 {
		return fmt.Errorf("usage: netractl incident diff A B [--json]")
	}
	var docs [2][]byte
	for i, f := range files {
		raw, err := readBundleFile(f)
		if err != nil {
			return err
		}
		if rep := incidentbundle.VerifyFile(raw); !rep.OK {
			return fmt.Errorf("%s does not verify (%s): refusing to compare", f, firstProblem(rep))
		}
		doc, _, _ := incidentbundle.Load(raw)
		docs[i] = doc
	}
	rep, err := incidentbundle.Diff(docs[0], docs[1])
	if err != nil {
		return err
	}
	if asJSON {
		x, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(x))
		return nil
	}
	fmt.Printf("A  %s  window %s .. %s  %s %s\nB  %s  window %s .. %s  %s %s\n", files[0], rep.A.WindowStart, rep.A.WindowEnd, rep.A.Version, rep.A.Mode,
		files[1], rep.B.WindowStart, rep.B.WindowEnd, rep.B.Version, rep.B.Mode)
	for _, n := range rep.Notes {
		fmt.Println("note: " + n)
	}
	for _, f := range rep.Identity {
		fmt.Printf("identity %s: %s -> %s\n", f.Path, f.A, f.B)
	}
	for _, s := range rep.Sections {
		if s.Identical {
			continue
		}
		fmt.Printf("\n[%s]\n", s.Section)
		for _, f := range s.Fields {
			fmt.Printf("  %s: %s -> %s\n", f.Path, f.A, f.B)
		}
		for _, l := range s.Lists {
			fmt.Printf("  %s: %d -> %d rows (+%d -%d ~%d)\n", l.List, l.CountA, l.CountB, l.AddedTotal, l.RemovedTotal, l.ChangedTotal)
			for _, a := range l.Added {
				fmt.Println("    + " + a)
			}
			for _, r := range l.Removed {
				fmt.Println("    - " + r)
			}
			for _, c := range l.Changed {
				parts := make([]string, 0, len(c.Fields))
				for _, f := range c.Fields {
					parts = append(parts, f.Path+" "+f.A+"->"+f.B)
				}
				fmt.Printf("    ~ %s  [%s]\n", c.Item, strings.Join(parts, ", "))
			}
		}
	}
	fmt.Println("\n" + rep.Summary)
	return nil
}

// sealKey reads the shared seal key from --key-file or NETRA_INCIDENT_SEAL_KEY.
// The key never appears on the command line and is never written anywhere.
func sealKey(keyFile string) ([]byte, error) {
	var key []byte
	if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		key = bytes.TrimSpace(b)
	} else if v := os.Getenv("NETRA_INCIDENT_SEAL_KEY"); v != "" {
		key = []byte(strings.TrimSpace(v))
	} else {
		return nil, fmt.Errorf("a seal key is required: --key-file FILE or NETRA_INCIDENT_SEAL_KEY")
	}
	if len(key) < incidentbundle.MinSealKeyBytes {
		return nil, fmt.Errorf("seal key must be at least %d bytes", incidentbundle.MinSealKeyBytes)
	}
	return key, nil
}

// incidentSeal writes a detached HMAC seal for a bundle (offline).
func incidentSeal(args []string) error {
	var files []string
	var keyFile, out string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--key-file" && i+1 < len(args):
			i++
			keyFile = args[i]
		case a == "--out" && i+1 < len(args):
			i++
			out = args[i]
		case strings.HasPrefix(a, "--"):
			return fmt.Errorf("unknown incident seal flag %s\n%s", a, incidentUsage)
		default:
			files = append(files, a)
		}
	}
	if len(files) != 1 {
		return fmt.Errorf("usage: netractl incident seal FILE [--key-file KEY] [--out FILE.seal]")
	}
	key, err := sealKey(keyFile)
	if err != nil {
		return err
	}
	data, err := readBundleFile(files[0])
	if err != nil {
		return err
	}
	s, err := incidentbundle.SealBundle(data, key, time.Now())
	if err != nil {
		return err
	}
	if out == "" {
		out = files[0] + ".seal"
	}
	x, _ := json.MarshalIndent(s, "", "  ")
	if err := os.WriteFile(out, append(x, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Printf("sealed %s\n  chain head %s  key id %s\n  wrote %s\n  share the key out of band; check with: netractl incident verify %s --seal %s --key-file KEY\n", files[0], s.BundleHead, s.KeyID, out, files[0], out)
	return nil
}

// incidentReport renders an offline post-incident draft from a bundle.
func incidentReport(args []string) error {
	var files []string
	var out string
	asJSON := false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--json":
			asJSON = true
		case a == "--out" && i+1 < len(args):
			i++
			out = args[i]
		case strings.HasPrefix(a, "--"):
			return fmt.Errorf("unknown incident report flag %s\n%s", a, incidentUsage)
		default:
			files = append(files, a)
		}
	}
	if len(files) != 1 {
		return fmt.Errorf("usage: netractl incident report FILE [--json] [--out FILE]")
	}
	data, err := readBundleFile(files[0])
	if err != nil {
		return err
	}
	rep, err := incidentbundle.BuildReport(data)
	if err != nil {
		return err
	}
	var text string
	if asJSON {
		x, _ := json.MarshalIndent(rep, "", "  ")
		text = string(x) + "\n"
	} else {
		text = rep.Markdown()
	}
	if out == "" {
		fmt.Print(text)
		return nil
	}
	if err := os.WriteFile(out, []byte(text), 0o600); err != nil {
		return err
	}
	fmt.Println("wrote " + out)
	return nil
}
