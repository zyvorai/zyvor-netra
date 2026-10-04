# Application collectors

The agent can scrape the status endpoints of common infrastructure software
next to the host, network and workload metrics (see [metrics.md](metrics.md)).
Application series go through the same pipeline: per-second store, streaming
to netrad, anomaly detection, metric alerts, exporters and the console.

Collectors are **read-only clients**. They issue `GET` requests or read-only
protocol commands (`INFO`, `stats`). They never write to an application,
change its configuration or run admin commands.

## Supported kinds

| Kind | Target | What is collected |
|---|---|---|
| `nginx` | `url` of `stub_status` | active connections, reading/writing/waiting, accepted vs handled, requests/s |
| `apache` | `url` of `mod_status` with `?auto` | requests/s, bytes/s, busy/idle workers, connections, uptime, scoreboard |
| `haproxy` | `url` of the stats CSV (`;csv`) | per frontend/backend/server sessions, bytes, errors, HTTP response classes, status |
| `redis` | `address` (`host:port`) | clients, memory and fragmentation, commands/s, keyspace hits and misses, evictions and expirations, network, connections, RDB changes, replication, keys per DB |
| `memcached` | `address` | connections, operations/s, get hits and misses, memory, items, evictions, network |
| `envoy` | `url` of `/stats/prometheus` | server liveness and memory, upstream cluster connections, requests, timeouts, retries, response classes, membership, downstream HTTP |
| `coredns` | `url` of `/metrics` | requests, responses by rcode, request duration (mean), cache entries/hits/misses, forwards, panics |
| `etcd` | `url` of `/metrics` | leader, leader changes, proposals, DB size, keys, WAL fsync and backend commit duration (mean), peer RTT, gRPC traffic |
| `prometheus` | any Prometheus text endpoint | whatever `include`/`exclude` select |

Each instance produces contexts named `<kind>.<metric>` (for example
`redis.commands` or `nginx.connections`) with charts named
`<kind>_<name>.<metric>`, labelled `app_name` plus any operator labels.
`apps.up` has one dimension per application (`kind/name`): 1 when the last
scrape succeeded and 0 when it failed.

For `envoy`, `coredns` and `etcd`, a fixed set of useful metrics is collected
unless `include` overrides it.

### Prometheus endpoints

The `prometheus` kind (and the three presets above) parses the text
exposition format:

- Counters become per-second rates and gauges stay absolute.
- Histograms and summaries contribute `_sum` and `_count` rates plus a
  lifetime mean (`_mean` = sum/count). Buckets and quantiles are skipped to
  bound cardinality.
- Each label set becomes one dimension (`code=200,method=GET`; `value` when
  there are no labels).
- At most `max_series` series per instance (default 2,000) are kept.

## Configuration

Applications are listed in a YAML file, `NETRA_APPS_CONFIG` (default
`/etc/netra/apps.yaml`). A missing file is not an error.

```yaml
apps:
  - kind: nginx
    name: edge
    url: http://127.0.0.1:8080/nginx_status
  - kind: redis
    name: cache
    address: 10.0.4.12:6379
    password_env: REDIS_CACHE_PASSWORD
  - kind: prometheus
    name: postgres
    url: http://127.0.0.1:9187/metrics      # postgres_exporter
    include: ["pg_up", "pg_stat_database_*", "pg_locks_count"]
    labels: {team: data}
  - kind: haproxy
    name: ingress
    url: https://lb.internal:8404/stats;csv
    username_env: HAPROXY_USER
    password_env: HAPROXY_PASSWORD
    insecure_skip_verify: true
    timeout: 3s
```

| Field | Meaning |
|---|---|
| `kind` | One of the kinds above (required). An unknown kind rejects the whole file. |
| `name` | Instance name; defaults to the kind. `kind/name` must be unique. |
| `url` | HTTP(S) endpoint; required for every kind except `redis` and `memcached`. |
| `address` | `host:port`; required for `redis` and `memcached`. |
| `username_env`, `password_env` | Names of environment variables holding credentials: HTTP basic auth, or Redis `AUTH`. |
| `bearer_env` | Name of an environment variable holding a bearer token (HTTP). Takes precedence over basic auth. |
| `include`, `exclude` | Metric-name globs for Prometheus endpoints. |
| `max_series` | Series cap per instance, default 2,000. |
| `labels` | Extra chart labels. |
| `insecure_skip_verify` | Skip TLS verification for this instance only. |
| `timeout` | Per-scrape timeout, default `2s`. |

| Variable (agent) | Default | Meaning |
|---|---|---|
| `NETRA_APPS_CONFIG` | `/etc/netra/apps.yaml` | Config file. |
| `NETRA_APPS_DISCOVERY` | `false` | Find applications listening on the host (below). |
| `NETRA_APPS_EVERY` | `5s` | Scrape interval. |

With no config file and discovery off, the collector does not run.

### Credentials

Credentials never appear in the config file. The `*_env` fields name
environment variables that the operator populates, typically from a Secret
mounted as environment variables. **Netra never reads Kubernetes Secrets
through the API** to find credentials, and never takes them from a process's
environment or command line.

A failing application is retried with backoff (up to ten scrape intervals)
and reported in `apps.up`. Failures are logged at debug level on the first
failure and every 60th after that.

## Discovery

With `NETRA_APPS_DISCOVERY=true` the agent scans once a minute for supported
software listening in the **host network namespace**:

1. It lists TCP listening sockets from `/proc/1/net/tcp` and `tcp6`.
2. For each process in the host network namespace, it reads the 15-byte
   kernel `comm` (`nginx`, `httpd`, `apache2`, `haproxy`, `redis-server`,
   `memcached`, `envoy`, `coredns`, `etcd`, `openresty`, or a name ending
   in `_exporter`) and its socket inodes from `/proc/<pid>/fd`.
3. It matches the inodes to the listeners and builds candidates on the
   well-known paths and ports for that kind (for example `/nginx_status` and
   `/stub_status` for nginx, `/metrics` for exporters). Wildcard binds are
   probed on `127.0.0.1`.

Discovery reads only `comm`, the network namespace link and the socket
inodes. It **never reads `cmdline` or `environ`**. Discovered applications
get no credentials. A guessed endpoint that fails three times in a row is
retried every 10 minutes, and an application whose process exits is dropped.
A configured application with the same `kind/name` takes precedence.

Pods with their own network namespace are not discovered; list them in the
config file by Service or pod address instead. Discovery needs the host PID
namespace, so the Helm chart sets `hostPID: true` on the agent only when
discovery is enabled.

## Helm

```yaml
metricsPlatform:
  apps:
    discovery: false
    every: 5s
    config: |
      apps:
        - kind: redis
          name: cache
          address: redis.cache.svc:6379
          password_env: REDIS_PASSWORD
    existingSecret: netra-app-credentials   # keys become env vars
```

`config` is rendered into the `netra-apps` ConfigMap and mounted at
`/etc/netra/apps/apps.yaml`. `existingSecret` is attached to the agent with
`envFrom`, so a key named `REDIS_PASSWORD` satisfies `password_env:
REDIS_PASSWORD`.

## PostgreSQL and MySQL

There is no native PostgreSQL or MySQL collector. Logging in to a database
would mean a database driver dependency and database credentials in the
agent, and the queries worth running differ from site to site. Instead, run
the standard [postgres_exporter](https://github.com/prometheus-community/postgres_exporter)
or [mysqld_exporter](https://github.com/prometheus/mysqld_exporter) and point
a `prometheus` entry at it (see the example above). With discovery on, an
exporter listening on the host is found by its `_exporter` comm.

## Limits

- Discovery covers host-network processes only.
- Histogram percentiles are not reconstructed; use the mean, or chart the
  exporter's own quantile gauges with `include`.
- Application metrics are polled every `NETRA_APPS_EVERY` (5 seconds by
  default), not every second.
