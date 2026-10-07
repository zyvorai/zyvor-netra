// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package intel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

type RefreshConfig struct {
	URL           string
	Interval, TTL time.Duration
}

func (c RefreshConfig) Validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("intel source must be an HTTPS URL without userinfo or fragment")
	}
	if c.Interval < time.Minute || c.Interval > 24*time.Hour || c.TTL < 2*c.Interval || c.TTL > 30*24*time.Hour {
		return errors.New("intel interval must be 1m..24h and TTL between twice the interval and 720h")
	}
	return nil
}
func (f *Feed) Refresh(ctx context.Context, c RefreshConfig, transport http.RoundTripper) (err error) {
	defer func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lastRefresh = time.Now().UTC()
		// Never echo a URL/token or a server response into public feed status.
		f.refreshError = ""
		if err != nil {
			f.refreshError = "refresh failed; previous feed retained"
		}
	}()
	if err = c.Validate(); err != nil {
		return err
	}
	revision := f.Status().Revision
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return errors.New("invalid feed request")
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return errors.New("feed download failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New("feed source returned non-200")
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20+1))
	if err != nil || len(b) > 1<<20 {
		return errors.New("feed body too large or unreadable")
	}
	p, err := Parse(string(b))
	if err != nil || p.Count == 0 || p.Dropped > 0 {
		return errors.New("feed is empty, incomplete or invalid")
	}
	if ctx.Err() != nil {
		return errors.New("feed refresh cancelled")
	}
	u, _ := url.Parse(c.URL)
	u.RawQuery = ""
	u.ForceQuery = false
	_, err = f.Put(p, u.String(), "scheduled refresh", c.TTL, &revision)
	return err
}
func (f *Feed) RunRefresh(ctx context.Context, c RefreshConfig) {
	if f == nil || c.Validate() != nil {
		return
	}
	tick := time.NewTicker(c.Interval)
	defer tick.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		_ = f.Refresh(ctx, c, nil)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
