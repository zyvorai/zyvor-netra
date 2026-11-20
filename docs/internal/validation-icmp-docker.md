# ICMP and Docker diagnostics validation

Base: `c8955266f24423a9214332331614a41df6b35dae` (main, 2026-09-13).
Validation performed locally on 2026-09-13; these results are not GitHub CI results.

## Passed

- `make fmt` with Go 1.27.1. Incidental formatting changes outside this task were removed.
- `go test -race ./cmd/netractl ./internal/agent`.
- `go vet ./cmd/netractl ./internal/agent`.
- `go build ./cmd/...`.
- `GOOS=darwin GOARCH=arm64 go build ./cmd/netractl` (cross-compilation only).
- CLI subprocess smoke: agent JSON through stdin produces `icmp-pmtu` with IPv6,
  interface index, direction, observation count, and advertised MTU 1280.
- `npm --prefix web run test`: 62 tests in 10 files.
- `npm --prefix web run build`: TypeScript + Vite production build. Vite reports
  the existing large-bundle warning; the build succeeds.
- C host tests for ICMP, IPv6 extension walking, L7 parsing, and map ABI layout,
  with `cc -std=c11 -O2 -Wall -Wextra -Werror` and `-Ibpf` for parser tests.
- Full BPF compilation with Debian clang 19.1.7:
  `clang-19 -target bpfel -O2 -g -Wall -Wextra -Werror -I/usr/include/x86_64-linux-gnu -c bpf/netra_tc.c -o /tmp/netra-icmp-tc.o`.
- `git diff --check`.

## Failed or not verified

`go test ./...` was run. Every package passes except `internal/procmeta`, where
seven pre-existing tests fail with `procmeta: process not found`:

- `TestCacheHitReturnsSameValue`
- `TestCacheSweep`
- `TestCacheExpiredEntryIsRefreshed`
- `TestReadCgroupSelf`
- `TestReadSelf`
- `TestReadIsStable`
- `TestReadSelfSaneSummary`

The same seven failures reproduce from an untouched archive of the base commit's
`internal/procmeta` package, using the same Go toolchain and module files. No files
in that package were changed. This runtime cannot expose the process metadata
those tests expect. The full suite must be rerun on a normal Linux CI host.

`TestDockerUnixTransport` skips on this runtime's `EPERM` socket denial. Docker
HTTP parsing, request paths, no bearer-token forwarding, response bounds/errors,
restart and cgroup-migration rejection, cgroup path validation, scope isolation,
and 64-bit identity preservation run using an in-memory HTTP transport. A real
Docker daemon, host cgroup lookup, and Unix-socket transport have not been tested
here. The socket test runs on hosts that permit Unix sockets.

The runtime has no effective Linux capabilities. The BPF object has not been
loaded into a live kernel or exercised on a veth/TC datapath. Verifier acceptance,
live packet accounting, and performance remain rollout gates; a successful BPF
compile does not establish them. See `docs/icmp-diagnostics.md` for live checks.

GitHub publication was attempted through the selected plugin. Branch creation
returned an internal connector error. No remote branch or PR was confirmed.
