// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package metricalert evaluates threshold and anomaly-rate rules against the
// per-second metrics store and publishes transitions through notify. It is
// read-only with respect to the datapath: a rule can raise an alert, never
// change mode, rules or policy. See docs/metric-alerts.md.
package metricalert

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed defaults.yaml
var defaultRules []byte

// Rule is one alert definition as written in YAML.
type Rule struct {
	Name       string             `yaml:"alarm" json:"name"`
	Context    string             `yaml:"on" json:"context"`
	Charts     string             `yaml:"charts,omitempty" json:"charts,omitempty"`
	Dimensions string             `yaml:"dimensions,omitempty" json:"dimensions,omitempty"`
	Labels     map[string]string  `yaml:"labels,omitempty" json:"labels,omitempty"`
	Lookup     string             `yaml:"lookup" json:"lookup"`
	Aggregate  string             `yaml:"aggregate,omitempty" json:"aggregate,omitempty"`
	Per        string             `yaml:"per,omitempty" json:"per,omitempty"`
	Vars       map[string]float64 `yaml:"vars,omitempty" json:"vars,omitempty"`
	Calc       string             `yaml:"calc,omitempty" json:"calc,omitempty"`
	Warn       string             `yaml:"warn,omitempty" json:"warn,omitempty"`
	Crit       string             `yaml:"crit,omitempty" json:"crit,omitempty"`
	Every      string             `yaml:"every,omitempty" json:"every,omitempty"`
	DelayUp    string             `yaml:"delay_up,omitempty" json:"delayUp,omitempty"`
	DelayDown  string             `yaml:"delay_down,omitempty" json:"delayDown,omitempty"`
	Repeat     string             `yaml:"repeat,omitempty" json:"repeat,omitempty"`
	Units      string             `yaml:"units,omitempty" json:"units,omitempty"`
	Class      string             `yaml:"class,omitempty" json:"class,omitempty"`
	Info       string             `yaml:"info,omitempty" json:"info,omitempty"`
	Enabled    *bool              `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Source     string             `yaml:"-" json:"source"`
}

type ruleFile struct {
	Alerts []Rule `yaml:"alerts"`
}

// lookup functions accepted in "lookup: <fn> -<window>".
var lookupFns = map[string]string{
	"average": "avg", "avg": "avg", "mean": "avg",
	"min": "min", "max": "max", "sum": "sum", "last": "last",
	"median": "p50", "p50": "p50", "p90": "p90", "p95": "p95", "p99": "p99",
	"anomaly-rate": "anomaly-rate", "anomaly_rate": "anomaly-rate",
}

type compiled struct {
	Rule
	fn        string
	window    time.Duration
	charts    []string
	dims      []string
	calc      *Expr
	warn      *Expr
	crit      *Expr
	every     time.Duration
	delayUp   time.Duration
	delayDown time.Duration
	repeat    time.Duration
}

func splitGlobs(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '|' })
	if len(f) == 1 && f[0] == "*" {
		return nil
	}
	return f
}

func parseDur(s string, d time.Duration) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return d, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func compile(r Rule) (*compiled, error) {
	if r.Name == "" {
		return nil, errors.New("alarm name is required")
	}
	if r.Context == "" {
		return nil, fmt.Errorf("%s: on (context) is required", r.Name)
	}
	c := &compiled{Rule: r, charts: splitGlobs(r.Charts), dims: splitGlobs(r.Dimensions)}
	f := strings.Fields(r.Lookup)
	if len(f) != 2 {
		return nil, fmt.Errorf("%s: lookup must be '<function> -<window>'", r.Name)
	}
	fn, ok := lookupFns[strings.ToLower(f[0])]
	if !ok {
		return nil, fmt.Errorf("%s: unknown lookup function %q", r.Name, f[0])
	}
	c.fn = fn
	w, err := parseDur(strings.TrimPrefix(f[1], "-"), 0)
	if err != nil || w < time.Second || w > 31*24*time.Hour {
		return nil, fmt.Errorf("%s: bad lookup window %q", r.Name, f[1])
	}
	c.window = w
	switch r.Aggregate {
	case "", "sum", "avg", "min", "max":
	default:
		return nil, fmt.Errorf("%s: aggregate must be sum, avg, min or max", r.Name)
	}
	switch r.Per {
	case "":
		c.Per = "chart"
	case "chart", "dimension", "node":
	default:
		return nil, fmt.Errorf("%s: per must be chart, dimension or node", r.Name)
	}
	for _, e := range []struct {
		src string
		dst **Expr
	}{{r.Calc, &c.calc}, {r.Warn, &c.warn}, {r.Crit, &c.crit}} {
		x, err := Compile(e.src)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Name, err)
		}
		*e.dst = x
	}
	if c.warn == nil && c.crit == nil {
		return nil, fmt.Errorf("%s: needs warn or crit", r.Name)
	}
	durs := []struct {
		src string
		def time.Duration
		dst *time.Duration
	}{{r.Every, 10 * time.Second, &c.every}, {r.DelayUp, 0, &c.delayUp}, {r.DelayDown, 0, &c.delayDown}, {r.Repeat, 0, &c.repeat}}
	for _, d := range durs {
		v, err := parseDur(d.src, d.def)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("%s: bad duration %q", r.Name, d.src)
		}
		*d.dst = v
	}
	if c.every < time.Second {
		c.every = time.Second
	}
	return c, nil
}

// ParseRules parses one YAML document of rules.
func ParseRules(data []byte, source string) ([]Rule, error) {
	var f ruleFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	for i := range f.Alerts {
		f.Alerts[i].Source = source
	}
	return f.Alerts, nil
}

// DefaultRules returns the embedded rule pack.
func DefaultRules() []Rule {
	rs, err := ParseRules(defaultRules, "builtin")
	if err != nil {
		panic(err)
	}
	return rs
}

// LoadRules returns the built-in pack (unless includeDefaults is false)
// overlaid with *.yaml and *.yml files from dirs. A rule with the same name
// replaces an earlier one; enabled: false removes it.
func LoadRules(includeDefaults bool, dirs ...string) ([]Rule, error) {
	byName := map[string]Rule{}
	var order []string
	add := func(rs []Rule) {
		for _, r := range rs {
			if _, ok := byName[r.Name]; !ok {
				order = append(order, r.Name)
			}
			byName[r.Name] = r
		}
	}
	if includeDefaults {
		add(DefaultRules())
	}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			ext := filepath.Ext(e.Name())
			if !e.IsDir() && (ext == ".yaml" || ext == ".yml") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			p := filepath.Join(dir, n)
			data, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			rs, err := ParseRules(data, p)
			if err != nil {
				return nil, err
			}
			add(rs)
		}
	}
	out := make([]Rule, 0, len(order))
	for _, n := range order {
		r := byName[n]
		if r.Enabled != nil && !*r.Enabled {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
