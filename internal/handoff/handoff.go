package handoff

import (
	"fmt"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/auditstats"
	"github.com/zyvorai/netra/internal/coverage"
	"github.com/zyvorai/netra/internal/fleet"
	"github.com/zyvorai/netra/internal/playbook"
	"github.com/zyvorai/netra/internal/reasons"
	"github.com/zyvorai/netra/internal/report"
)

type Pack struct {
	GeneratedAt time.Time          `json:"generatedAt"`
	Report      report.Snapshot    `json:"report"`
	Playbook    playbook.Book      `json:"playbook"`
	Coverage    coverage.Matrix    `json:"coverage"`
	Fleet       fleet.Inventory    `json:"fleet"`
	Audit       auditstats.Summary `json:"audit"`
	Reasons     reasons.Histogram  `json:"reasons"`
}

func Build(snap report.Snapshot, cov coverage.Matrix, fl fleet.Inventory, audit auditstats.Summary, rs reasons.Histogram, now time.Time) Pack {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return Pack{GeneratedAt: now.UTC(), Report: snap, Playbook: playbook.Build(snap), Coverage: cov, Fleet: fl, Audit: audit, Reasons: rs}
}

func Markdown(p Pack) string {
	var sb strings.Builder
	sb.WriteString("# Netra on-call handoff\n\n")
	fmt.Fprintf(&sb, "Generated %s.\n\n", p.GeneratedAt.UTC().Format(time.RFC3339))
	sb.WriteString(report.Markdown(p.Report))
	sb.WriteString("\n")
	sb.WriteString(playbook.Markdown(p.Playbook))
	fmt.Fprintf(&sb, "\n## Fleet\n\n- Agents: %d (%d stale)\n- Workloads: %d\n\n## Coverage\n\n- Detached programs: %d\n- Missing maps: %d\n- Quiet: %v\n\n## Drop reasons\n\n- Events: %d (%d blocked)\n\nThis pack is observe-only. It does not apply policy or extend a lease.\n", p.Fleet.AgentCount, p.Fleet.StaleAgents, p.Fleet.Workloads, p.Coverage.DetachedPrograms, p.Coverage.MissingMapEntries, p.Coverage.Quiet, p.Reasons.Total, p.Reasons.Blocked)
	return sb.String()
}
