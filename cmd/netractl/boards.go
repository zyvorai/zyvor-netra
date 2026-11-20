// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
)

func talkersCmd(args []string) error {
	asJSON := false
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		}
	}
	out, status, err := doRequest("GET", "/api/v1/talkers", nil, nil)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("%s: %s", statusText(status), strings.TrimSpace(string(out)))
	}
	if asJSON {
		fmt.Print(string(out))
		if len(out) == 0 || out[len(out)-1] != '\n' {
			fmt.Println()
		}
		return nil
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		fmt.Print(string(out))
		return nil
	}
	printTalkers(v, os.Stdout)
	return nil
}

func scorecardCmd(args []string) error {
	asJSON := false
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		}
	}
	out, status, err := doRequest("GET", "/api/v1/scorecard", nil, nil)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("%s: %s", statusText(status), strings.TrimSpace(string(out)))
	}
	if asJSON {
		fmt.Print(string(out))
		if len(out) == 0 || out[len(out)-1] != '\n' {
			fmt.Println()
		}
		return nil
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		fmt.Print(string(out))
		return nil
	}
	printScorecard(v, os.Stdout)
	return nil
}

func printTalkers(v map[string]any, w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DESTINATION\tPACKETS\tBYTES\tBLOCKED\tNODES")
	rows := boardList(v["talkers"])
	if len(rows) == 0 {
		rows = boardList(v["items"])
	}
	if len(rows) == 0 {
		rows = boardList(v["destinations"])
	}
	for _, row := range rows {
		m := boardObj(row)
		dest := boardFirst(boardStr(m["destination"]), boardStr(m["ip"]), boardStr(m["address"]), boardStr(m["name"]))
		fmt.Fprintf(tw, "%s\t%.0f\t%.0f\t%.0f\t%s\n", dest, boardNum(m["packets"]), boardNum(m["bytes"]), boardNum(m["blocked"]), boardStr(m["nodes"]))
	}
	tw.Flush()
	if len(rows) == 0 {
		fmt.Fprintln(w, "(no talkers)")
	}
}

func printScorecard(v map[string]any, w io.Writer) {
	fmt.Fprintf(w, "score=%.0f  grade=%s  mode=%s\n", boardNum(v["score"]), boardFirst(boardStr(v["grade"]), boardStr(v["letter"])), boardStr(v["mode"]))
	if note := boardStr(v["note"]); note != "" {
		fmt.Fprintf(w, "note: %s\n", note)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DIMENSION\tSCORE\tSTATUS")
	for _, row := range boardList(v["dimensions"]) {
		m := boardObj(row)
		fmt.Fprintf(tw, "%s\t%.0f\t%s\n", boardFirst(boardStr(m["name"]), boardStr(m["id"])), boardNum(m["score"]), boardStr(m["status"]))
	}
	tw.Flush()
}

func statusText(code int) string {
	if code == 0 {
		return "error"
	}
	return fmt.Sprintf("%d", code)
}

func boardList(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}

func boardObj(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func boardStr(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func boardNum(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		f, _ := t.Float64()
		return f
	default:
		return 0
	}
}

func boardFirst(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "—"
}

func boardDig(v any, path string) any {
	cur := v
	for _, key := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[key]
	}
	return cur
}

// surfaceTableCmd fetches path and prints a human table unless --json is set.
func surfaceTableCmd(path string, listKeys []string, headers []string, cols func(map[string]any) []string, args []string) error {
	asJSON := false
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		}
	}
	out, status, err := doRequest("GET", path, nil, nil)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("%s: %s", statusText(status), strings.TrimSpace(string(out)))
	}
	if asJSON {
		fmt.Print(string(out))
		if len(out) == 0 || out[len(out)-1] != '\n' {
			fmt.Println()
		}
		return nil
	}
	var v any
	if err := json.Unmarshal(out, &v); err != nil {
		fmt.Print(string(out))
		return nil
	}
	var rows []any
	if m, ok := v.(map[string]any); ok {
		for _, k := range listKeys {
			if got := boardDig(m, k); got != nil {
				if list := boardList(got); len(list) > 0 {
					rows = list
					break
				}
			}
		}
	} else if list := boardList(v); len(list) > 0 {
		rows = list
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, row := range rows {
		cells := cols(boardObj(row))
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	tw.Flush()
	if len(rows) == 0 {
		fmt.Println("(no rows)")
	}
	return nil
}
