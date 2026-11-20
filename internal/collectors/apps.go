// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// AppConfig is one application endpoint. Credentials are never written in
// the file: PasswordEnv, UsernameEnv and BearerEnv name environment
// variables the operator populates (for example from a Secret mounted as
// env). Netra never reads Kubernetes Secrets through the API for this.
type AppConfig struct {
	Kind        string            `yaml:"kind" json:"kind"` // nginx, apache, haproxy, redis, memcached, envoy, coredns, etcd, prometheus
	Name        string            `yaml:"name" json:"name"`
	URL         string            `yaml:"url,omitempty" json:"url,omitempty"`
	Address     string            `yaml:"address,omitempty" json:"address,omitempty"` // host:port for redis/memcached
	UsernameEnv string            `yaml:"username_env,omitempty" json:"usernameEnv,omitempty"`
	PasswordEnv string            `yaml:"password_env,omitempty" json:"passwordEnv,omitempty"`
	BearerEnv   string            `yaml:"bearer_env,omitempty" json:"bearerEnv,omitempty"`
	Include     []string          `yaml:"include,omitempty" json:"include,omitempty"` // prometheus metric name globs
	Exclude     []string          `yaml:"exclude,omitempty" json:"exclude,omitempty"`
	MaxSeries   int               `yaml:"max_series,omitempty" json:"maxSeries,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	InsecureTLS bool              `yaml:"insecure_skip_verify,omitempty" json:"insecureSkipVerify,omitempty"`
	Timeout     time.Duration     `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	discovered  bool
}

type appsFile struct {
	Apps []AppConfig `yaml:"apps"`
}

// LoadAppsConfig reads an apps YAML file ("apps: [...]"). A missing file is
// not an error.
func LoadAppsConfig(path string) ([]AppConfig, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f appsFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range f.Apps {
		if err := f.Apps[i].normalize(); err != nil {
			return nil, fmt.Errorf("%s: app %d: %w", path, i, err)
		}
	}
	return f.Apps, nil
}

func (c *AppConfig) normalize() error {
	c.Kind = strings.ToLower(strings.TrimSpace(c.Kind))
	if _, ok := appKinds[c.Kind]; !ok {
		return fmt.Errorf("unknown kind %q", c.Kind)
	}
	if c.Name == "" {
		c.Name = c.Kind
	}
	switch c.Kind {
	case "redis", "memcached":
		if c.Address == "" {
			return fmt.Errorf("%s %s: address is required", c.Kind, c.Name)
		}
	default:
		if c.URL == "" {
			return fmt.Errorf("%s %s: url is required", c.Kind, c.Name)
		}
	}
	if c.Timeout <= 0 {
		c.Timeout = 2 * time.Second
	}
	if c.MaxSeries <= 0 {
		c.MaxSeries = 2000
	}
	return nil
}

func (c AppConfig) id() string { return c.Kind + "/" + c.Name }

// appChart builds a chart for one app instance: context "<kind>.<metric>",
// chart id "<kind>_<name>.<metric>", labels app_name plus operator labels.
func (c AppConfig) chart(metric, family, units, title, typ string) Chart {
	lbl := map[string]string{"app_name": c.Name}
	for k, v := range c.Labels {
		lbl[k] = v
	}
	return Chart{Context: c.Kind + "." + metric, ID: c.Kind + "_" + sanitizeID(c.Name) + "." + metric, Family: family, Units: units, Title: title, Type: typ, Labels: lbl}
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// appCollector scrapes one application.
type appCollector interface {
	collect(ctx context.Context, e *Emitter) error
}

var appKinds = map[string]func(AppConfig) appCollector{
	"nginx":      func(c AppConfig) appCollector { return &nginxApp{cfg: c} },
	"apache":     func(c AppConfig) appCollector { return &apacheApp{cfg: c} },
	"haproxy":    func(c AppConfig) appCollector { return &haproxyApp{cfg: c} },
	"redis":      func(c AppConfig) appCollector { return &redisApp{cfg: c} },
	"memcached":  func(c AppConfig) appCollector { return &memcachedApp{cfg: c} },
	"envoy":      func(c AppConfig) appCollector { return newPromApp(withDefaults(c, envoyInclude)) },
	"coredns":    func(c AppConfig) appCollector { return newPromApp(withDefaults(c, corednsInclude)) },
	"etcd":       func(c AppConfig) appCollector { return newPromApp(withDefaults(c, etcdInclude)) },
	"prometheus": func(c AppConfig) appCollector { return newPromApp(c) },
}

func withDefaults(c AppConfig, include []string) AppConfig {
	if len(c.Include) == 0 {
		c.Include = include
	}
	return c
}

// httpGet fetches url with the app's auth and TLS settings, reading at most
// 8 MiB.
func (c AppConfig) httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "netra-agent")
	req.Header.Set("Accept", "text/plain;version=0.0.4, */*;q=0.5")
	if c.BearerEnv != "" {
		req.Header.Set("Authorization", "Bearer "+os.Getenv(c.BearerEnv))
	} else if c.UsernameEnv != "" || c.PasswordEnv != "" {
		req.SetBasicAuth(os.Getenv(c.UsernameEnv), os.Getenv(c.PasswordEnv))
	}
	client := plainClient
	if c.InsecureTLS {
		client = insecureClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

var (
	plainClient    = &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 2, IdleConnTimeout: time.Minute}}
	insecureClient = &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 2, IdleConnTimeout: time.Minute, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // operator opt-in per app
)

// AppStatus reports one configured or discovered application.
type AppStatus struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	Target     string    `json:"target"`
	Discovered bool      `json:"discovered"`
	OK         bool      `json:"ok"`
	LastError  string    `json:"lastError,omitempty"`
	LastOK     time.Time `json:"lastOk"`
}

type appEntry struct {
	cfg    AppConfig
	c      appCollector
	status AppStatus
	fails  int
	retry  time.Time
}

// Apps drives every configured application and, with Discover set, the
// applications found listening on this host. It runs as one collector so
// the scheduler sees a single slot; each app has its own timeout.
type Apps struct {
	Static   []AppConfig
	Discover bool
	Interval time.Duration // default 5s
	Log      *slog.Logger
	disc     *appDiscovery

	mu       sync.Mutex
	entries  map[string]*appEntry
	lastDisc time.Time
}

// NewApps builds the collector. cfg locates /proc for discovery.
func NewApps(cfg Config, static []AppConfig, discover bool, every time.Duration, log *slog.Logger) *Apps {
	if every <= 0 {
		every = 5 * time.Second
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	a := &Apps{Static: static, Discover: discover, Interval: every, Log: log, entries: map[string]*appEntry{}}
	if discover {
		a.disc = &appDiscovery{fs: fsys{proc: cfg.ProcRoot, sys: cfg.SysRoot}}
	}
	for _, c := range static {
		a.add(c)
	}
	return a
}

func (a *Apps) Info() Info { return Info{Name: "apps", Family: "apps", Every: a.Interval} }

func (a *Apps) add(c AppConfig) {
	if _, ok := a.entries[c.id()]; ok {
		return
	}
	mk := appKinds[c.Kind]
	if mk == nil {
		return
	}
	target := c.URL
	if target == "" {
		target = c.Address
	}
	a.entries[c.id()] = &appEntry{cfg: c, c: mk(c), status: AppStatus{ID: c.id(), Kind: c.Kind, Name: c.Name, Target: target, Discovered: c.discovered}}
}

// Statuses lists every application, sorted by id.
func (a *Apps) Statuses() []AppStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AppStatus, 0, len(a.entries))
	for _, e := range a.entries {
		out = append(out, e.status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (a *Apps) Collect(now time.Time, e *Emitter) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.disc != nil && now.Sub(a.lastDisc) >= time.Minute {
		a.lastDisc = now
		found := a.disc.scan()
		live := map[string]bool{}
		for _, c := range found {
			live[c.id()] = true
			a.add(c)
		}
		for id, en := range a.entries {
			// Discovered apps whose process went away are dropped; static
			// ones stay and report failures.
			if en.cfg.discovered && !live[id] {
				delete(a.entries, id)
			}
		}
	}
	ids := make([]string, 0, len(a.entries))
	for id := range a.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	up := Chart{Context: "apps.up", ID: "apps.up", Family: "apps", Units: "boolean", Title: "Application collectors reachable (1 up)"}
	for _, id := range ids {
		en := a.entries[id]
		if now.Before(en.retry) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), en.cfg.Timeout)
		err := en.c.collect(ctx, e)
		cancel()
		if err != nil {
			en.fails++
			en.status.OK, en.status.LastError = false, err.Error()
			if en.fails == 1 || en.fails%60 == 0 {
				a.Log.Debug("app collector failed", "app", id, "error", err)
			}
			// Back off failing apps: discovered guesses quickly give up.
			wait := time.Duration(min(en.fails, 10)) * a.Interval
			if en.cfg.discovered && en.fails >= 3 {
				wait = 10 * time.Minute
			}
			en.retry = now.Add(wait)
			e.Gauge(up, id, 0)
			continue
		}
		en.fails = 0
		en.status.OK, en.status.LastError, en.status.LastOK = true, "", now
		e.Gauge(up, id, 1)
	}
	return nil
}
