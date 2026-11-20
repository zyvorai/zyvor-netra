# DNS diagnostics extension: validation

This extension builds on implementation commit
`214d63a028c4b0b787c6bc2339b5b9266ddda7e4` (the previous ICMP/Docker ZIP).

## Passed in this run

- Go 1.27.1: `make fmt` (unrelated formatting-only changes removed).
- `go test -race ./cmd/netractl ./internal/agent`.
- `go vet ./cmd/netractl ./internal/agent`.
- `go build ./cmd/netractl`.
- CLI subprocess/stdin smoke: combined DNS NXDOMAIN and ICMP/interface-name
  findings, plus pod/name-scoped DNS with ICMP correctly excluded.
- `npm --prefix web run test`: 70 tests in 12 files.
- `npm --prefix web run build`: TypeScript and production Vite build pass;
  the existing large-bundle warning remains.
- `git diff --check`.

New tests cover response-code classification, omitted zero RCODE, native-event
qualification, terminal/HTML escaping, scope isolation, stale reports, old/future
Health events, missing workload metadata, row limits, and interface-name fallback.

## Existing environment limitations

`go test ./...` was run again. Every package passes except `internal/procmeta`,
with the same seven `procmeta: process not found` failures documented and reproduced
on the unchanged base in `validation-icmp-docker.md`. No files in that package
were changed. The Docker Unix-socket test skips under this runtime's EPERM denial.

This extension does not change BPF source, maps, parser logic, or event ABI. The
prior package's successful BPF compilation and C parser tests remain the previous
validation record, not newly rerun kernel tests. Live-kernel verifier/TC traffic
and real Docker-host validation remain outstanding for the cumulative package.

No GitHub PR was published as part of this ZIP delivery. Apply on the documented
base (or apply the upgrade-only patch after the previous package) and run CI plus
the host-dependent checks before deployment.
