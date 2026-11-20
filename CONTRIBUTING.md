# Contributing

1. Open an issue describing the behavior or change.
2. Keep the Cilium/Netra responsibility boundary intact: never modify or pin over Cilium-owned BPF maps.
3. Add tests for policy, API, filter or store behavior.
4. Run `make fmt`, `go test ./...`, `npm --prefix web run test`, and the eBPF compile gate before submitting a PR — these are exactly the checks `.github/workflows/ci.yml`'s `go`/`web`/`helm`/`ebpf` jobs run on every push, and are the project's current, living validation record (see `docs/internal/validation-v0.14.0.md` for a superseded, historical one-off snapshot from before CI covered all of this).
5. Contributions are accepted under the Zyvor Production License. Include the `LicenseRef-Zyvor-Production-1.0` SPDX header in new source files.
