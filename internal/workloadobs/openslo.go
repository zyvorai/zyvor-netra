// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package workloadobs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/zyvorai/netra/internal/slo"
)

// OpenSLO annotation keys. Netra's SLIs are a closed set of counter ratios, so
// the SLI is chosen by annotation rather than by interpreting a metric query.
const (
	AnnotationSLI       = "netra.zyvor.dev/sli"
	AnnotationNamespace = "netra.zyvor.dev/namespace"
	AnnotationWorkload  = "netra.zyvor.dev/workload"

	maxOpenSLOBytes = 256 << 10
)

type openSLODoc struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name        string            `yaml:"name"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Spec struct {
		BudgetingMethod string `yaml:"budgetingMethod"`
		TimeWindow      []struct {
			Duration  string `yaml:"duration"`
			IsRolling *bool  `yaml:"isRolling"`
		} `yaml:"timeWindow"`
		Objectives []struct {
			Target        *float64 `yaml:"target"`
			TargetPercent *float64 `yaml:"targetPercent"`
		} `yaml:"objectives"`
		Indicator *struct {
			Spec struct {
				ThresholdMetric any `yaml:"thresholdMetric"`
			} `yaml:"spec"`
		} `yaml:"indicator"`
	} `yaml:"spec"`
}

// ParseOpenSLO reads a multi-document YAML stream of OpenSLO v1 SLO objects
// (the subset Netra can honour) into SLO definitions.
//
// Supported: kind SLO; metadata.name; a single rolling timeWindow; budgetingMethod
// Occurrences (or unset); one objective with target (fraction, 0.999) or
// targetPercent (99.9); annotations netra.zyvor.dev/sli (required),
// netra.zyvor.dev/namespace and netra.zyvor.dev/workload. Everything else is
// rejected with a reason instead of being silently reinterpreted: Timeslices
// budgeting, calendar-aligned windows, multiple objectives and thresholdMetric
// (latency) indicators would all change what the number means, and Netra has no
// per-request latency to evaluate them against.
func ParseOpenSLO(data []byte) ([]slo.Definition, error) {
	if len(data) > maxOpenSLOBytes {
		return nil, fmt.Errorf("OpenSLO file is %d bytes; the limit is %d", len(data), maxOpenSLOBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []slo.Definition
	seen := map[string]bool{}
	for i := 1; ; i++ {
		var d openSLODoc
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("OpenSLO document #%d: %w", i, err)
		}
		if d.Kind == "" && d.Metadata.Name == "" && d.APIVersion == "" {
			continue // empty document between separators
		}
		where := fmt.Sprintf("OpenSLO document #%d (%q)", i, d.Metadata.Name)
		if !strings.HasPrefix(d.APIVersion, "openslo/v1") {
			return nil, fmt.Errorf("%s: apiVersion must be openslo/v1, got %q", where, d.APIVersion)
		}
		if d.Kind != "SLO" {
			return nil, fmt.Errorf("%s: kind %q is not supported, only SLO", where, d.Kind)
		}
		def, err := d.toDefinition()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		if seen[def.Name] {
			return nil, fmt.Errorf("%s: duplicate name", where)
		}
		seen[def.Name] = true
		out = append(out, def)
		if len(out) > maxSLOs {
			return nil, fmt.Errorf("OpenSLO file has more than %d SLOs", maxSLOs)
		}
	}
	return out, nil
}

func (d openSLODoc) toDefinition() (slo.Definition, error) {
	name := d.Metadata.Name
	if !sloNameRE.MatchString(name) {
		return slo.Definition{}, fmt.Errorf("metadata.name must match %s", sloNameRE)
	}
	sli := strings.TrimSpace(d.Metadata.Annotations[AnnotationSLI])
	if !validSLIs[sli] {
		return slo.Definition{}, fmt.Errorf("annotation %s must be %s or %s (Netra's SLIs are fixed counter ratios; there is no latency SLI)", AnnotationSLI, SLIHTTP5xx, SLIDNSFailure)
	}
	if d.Spec.Indicator != nil && d.Spec.Indicator.Spec.ThresholdMetric != nil {
		return slo.Definition{}, errors.New("thresholdMetric indicators are not supported: Netra has no per-request latency")
	}
	if m := d.Spec.BudgetingMethod; m != "" && m != "Occurrences" {
		return slo.Definition{}, fmt.Errorf("budgetingMethod %q is not supported, only Occurrences", m)
	}
	if len(d.Spec.TimeWindow) != 1 {
		return slo.Definition{}, errors.New("exactly one timeWindow is required")
	}
	tw := d.Spec.TimeWindow[0]
	if tw.IsRolling != nil && !*tw.IsRolling {
		return slo.Definition{}, errors.New("calendar-aligned timeWindow is not supported, only rolling")
	}
	if tw.Duration == "" {
		return slo.Definition{}, errors.New("timeWindow.duration is required")
	}
	win, err := parseWindow(tw.Duration)
	if err != nil {
		return slo.Definition{}, err
	}
	if len(d.Spec.Objectives) != 1 {
		return slo.Definition{}, errors.New("exactly one objective is required")
	}
	obj := d.Spec.Objectives[0]
	var pct float64
	switch {
	case obj.Target != nil && obj.TargetPercent != nil:
		return slo.Definition{}, errors.New("set only one of target and targetPercent")
	case obj.Target != nil:
		pct = *obj.Target * 100
	case obj.TargetPercent != nil:
		pct = *obj.TargetPercent
	default:
		return slo.Definition{}, errors.New("objective needs target or targetPercent")
	}
	if math.IsNaN(pct) || pct < 50 || pct >= 100 {
		return slo.Definition{}, fmt.Errorf("target must be at least 50%% and below 100%%, got %v%%", pct)
	}
	return slo.Definition{
		Name: name, SLI: sli, TargetPct: math.Round(pct*1e6) / 1e6, Window: win,
		Namespace: d.Metadata.Annotations[AnnotationNamespace],
		Workload:  d.Metadata.Annotations[AnnotationWorkload],
	}, nil
}

// LoadOpenSLOFile reads and parses an OpenSLO file.
func LoadOpenSLOFile(path string) ([]slo.Definition, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("NETRA_SLO_FILE: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxOpenSLOBytes+1))
	if err != nil {
		return nil, fmt.Errorf("NETRA_SLO_FILE: %w", err)
	}
	defs, err := ParseOpenSLO(data)
	if err != nil {
		return nil, fmt.Errorf("NETRA_SLO_FILE %s: %w", path, err)
	}
	return defs, nil
}
