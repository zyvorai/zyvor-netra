// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// A page must stay well under the 8 MiB response cap in do: 500 pods with
// full status are about 3 MiB.
const (
	listPageSize = 500
	listMaxPages = 400
)

// listPages walks a Kubernetes list endpoint with limit/continue, calling
// page with each raw response.
func (c *Client) listPages(ctx context.Context, p string, page func([]byte) error) error {
	sep := "?"
	if strings.Contains(p, "?") {
		sep = "&"
	}
	cont := ""
	for n := 0; ; n++ {
		q := p + sep + "limit=" + strconv.Itoa(listPageSize)
		if cont != "" {
			q += "&continue=" + url.QueryEscape(cont)
		}
		b, err := c.do(ctx, "GET", q, nil, "")
		if err != nil {
			return err
		}
		if err := page(b); err != nil {
			return err
		}
		var meta struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(b, &meta); err != nil {
			return err
		}
		if meta.Metadata.Continue == "" {
			return nil
		}
		if n+1 >= listMaxPages {
			return fmt.Errorf("list %s: more than %d pages", p, listMaxPages)
		}
		cont = meta.Metadata.Continue
	}
}

// listItems decodes every page's items into T.
func listItems[T any](ctx context.Context, c *Client, p string) ([]T, error) {
	var out []T
	err := c.listPages(ctx, p, func(b []byte) error {
		var l struct {
			Items []T `json:"items"`
		}
		if err := json.Unmarshal(b, &l); err != nil {
			return err
		}
		out = append(out, l.Items...)
		return nil
	})
	return out, err
}
