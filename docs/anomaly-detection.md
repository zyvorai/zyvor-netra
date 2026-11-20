# Anomaly detection

Every per-second metric dimension (see [metrics.md](metrics.md)) gets its own
unsupervised model. Each new sample is flagged anomalous or not before it is
stored, so every chart carries an anomaly ribbon, every query returns an
`anomalyRate` per bucket, and metric alerts can fire on the anomaly rate
instead of a hand-picked threshold. The implementation (`internal/anomaly`)
is stdlib-only Go with no ML library.

## How a model works

The approach follows Netdata's ML:

1. **Features.** The dimension's recent raw values are differenced (so a
   steady level or a steady slope looks normal), smoothed with a 3-sample
   moving average, and turned into lagged vectors of 6 values (the current
   point plus 5 lags).
2. **Training.** k-means with k=2 runs over up to 3,600 feature vectors from
   the training window. The initial centres are the vectors closest to and
   farthest from the origin, so training is deterministic. The anomaly
   threshold is the 99th percentile of the training vectors' distance to
   their nearest centre.
3. **Scoring.** A new sample is anomalous when its feature vector is farther
   from both centres than that threshold.

A model needs at least 300 feature vectors, about five minutes of data. Until
a dimension's model covers most of the training window, it is retrained every
10 minutes so a new node gets useful models quickly. After that it is retrained
on the regular schedule. Training is spread out, at most 200 models per tick,
so CPU cost stays flat.

A single anomalous bit means little on its own, because by construction about
1% of normal samples exceed the threshold. What matters is the **anomaly
rate**: the percentage of a dimension's, chart's or node's samples flagged in
a window. Rollup tiers keep the anomalous count per bucket, so the rate stays
available over 30-day windows.

## Where it runs

| Mode | Settings | Notes |
|---|---|---|
| On the agent (default) | `NETRA_METRICS_ML=true` | Trains on the node's own 1-hour tier-0 store and flags samples before they are streamed. |
| On netrad | agent `NETRA_METRICS_ML=false`, netrad `NETRA_METRICS_PARENT_ML=true` | Moves the CPU cost to netrad. One detector per node trains on that node's stream. A sample the agent already flagged stays flagged. |

| Variable | Default | Meaning |
|---|---|---|
| `NETRA_METRICS_ML` | `true` | Agent-side models on or off. |
| `NETRA_METRICS_ML_TRAIN_WINDOW` | `1h` | History used for each training, clipped to the data available. |
| `NETRA_METRICS_ML_TRAIN_EVERY` | `30m` | Retrain interval for mature models. |
| `NETRA_METRICS_PARENT_ML` | `false` | netrad-side scoring for agents that run with ML off. |

Helm: `metricsPlatform.agent.ml` (agent) and `metricsPlatform.parentMl` (netrad).

## Querying anomalies

`GET /api/v1/metrics/anomalies` returns:

- **`nodes`**: per node, the anomaly rate over the window, how many
  dimensions reported and how many had any anomalous sample, plus a 60-bucket
  anomaly-rate timeline.
- **`ranked`**: the most anomalous dimensions, ranked by anomaly rate, with
  their context, chart, labels and units.
- **`correlated`** (only when a highlight range is given): the dimensions
  whose value distribution changed most in the highlighted range compared
  with a baseline four times as long just before it. Change is measured by the
  two-sample Kolmogorov–Smirnov statistic. This answers "what changed here",
  including metrics whose models did not flag anything.

| Parameter | Meaning |
|---|---|
| `after`, `before` | unix seconds or negative relative seconds (default `-900`, `0`) |
| `nodes` | comma-separated globs |
| `top` | ranked and correlated entries returned (default 30, max 500) |
| `highlight_after`, `highlight_before` | range to correlate |

When the baseline is still inside tier 0, correlation uses 1-second samples.
Otherwise it uses 1-minute rollup averages.

```bash
netractl metrics anomalies --after -3600
netractl metrics anomalies --highlight-after -600 --highlight-before -300
```

MCP: `netra_metrics_anomalies` and the `netra://metrics/anomalies` resource.
In the console, the **Metric anomalies** view shows the timeline per node;
drag across it to rank the metrics that changed. Each chart's anomaly ribbon
and the Evidence panel (which lists co-anomalous metrics) use the same data.

## Alerting on anomalies

The `anomaly-rate` lookup function evaluates the percentage of samples
flagged in the window. `$anomaly_rate` is also available in any rule's
expressions:

```yaml
- alarm: network_anomaly_rate
  on: net.net
  lookup: anomaly-rate -10m
  units: "%"
  warn: '$this > (($status >= $WARNING) ? 20 : 40)'
  delay_down: 15m
```

The built-in rules `node_anomaly_rate` and `network_anomaly_rate` do this for
CPU and interface bandwidth; see [metric-alerts.md](metric-alerts.md).

## AI briefs

AI briefs and digests include the top anomalous dimensions, those at or above
10% over the last 15 minutes, as `metric-anomaly` findings next to raised
metric alerts. The AI agent's "metrics" intent points the operator at
`/api/v1/metrics/evidence` for the matching window. Anomalies do not change
the digest fingerprint (only alert rules do), so a noisy metric does not
cause "something changed" churn. The AI surface stays read-only (see
[ai.md](ai.md)).

## Limits

- Models are per dimension and univariate. Correlation across metrics comes
  from the ranked and KS views, not from a joint model.
- Seasonality longer than the training window (for example a daily batch
  job with a one-hour window) looks anomalous the first time each day. Raise
  `NETRA_METRICS_ML_TRAIN_WINDOW` along with `tier0Retention` if that matters.
- Models live in memory and are retrained after a restart; until then,
  samples are not flagged.
