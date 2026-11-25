# Research: round 5 (periodic egress, policy coverage, time-of-day baselines)

Searches run on 2026-11-25. Vendor and blog pages are claims, not facts. Items marked (unverified) rest on a search summary or could not be confirmed from a primary source.

| Source | What it says | Used in Netra |
|---|---|---|
| Elastic "Statistical Model Detected C2 Beaconing Activity" rule (fetched) | Periodic outbound traffic is flagged as low severity; monitoring agents and update tools are listed as false positives; needs an endpoint integration and process names for exclusions | Candidates are leads, not verdicts, and say so. Process comm is shown only when flow history already carries it |
| Black Hills InfoSec, beacons with Zeek and RITA (fetched) | Interval regularity, consistent sizes and connection count; large providers and automated tools score high | Same three signals, with coverage in place of a raw count |
| RITA beacon analysis source, `analysis/beacons.go` on GitHub (fetched) | Timestamp and size scores from median absolute deviation and Bowley skew, skew ignored when the interquartile range is under 10 | `internal/beacon` uses MAD and quartile skew with the same noise floor; its weights, gates and thresholds are its own |
| arXiv 2609.19091, "When Agents Look Like Beacons" (title only; body not readable) | Agent tool traffic may resemble beaconing (unverified) | Nothing |
| Kubernetes Network Policies documentation (fetched) | Isolation per direction, `policyTypes` default, additive rules, empty selector, undefined behaviour for `hostNetwork` pods | `internal/netpolcoverage` implements these rules and excludes hostNetwork pods |
| Search on NetworkPolicy coverage and simulation (unverified summaries) | Dry-run simulation and coverage-gap checks are common advice; no built-in Kubernetes coverage report was found | Coverage report; simulation stays with deny preview |
| SEI blog, choosing history for flow anomaly detection (fetched) | A consecutive history ignores seasonality; same hour of day suits daily cycles, same hour of week suits daily and weekly ones; history must be longer than the season | `baseline_mode=same-time` (median of the same time on earlier days). No day-of-week model, because the default 7-day retention holds one sample per weekday |

Ranked ideas not built: a day-of-week baseline (needs weeks of retention), NetworkPolicy rule simulation against observed flows, CiliumNetworkPolicy coverage (policy semantics differ enough to need their own evaluator), beacon detection across rotating addresses by DNS name.
