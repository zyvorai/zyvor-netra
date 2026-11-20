#!/usr/bin/env bash
# Netra — OIDC login + RBAC + metrics-token unit gate (no root, no network)
#
# Dedicated gate so a regression in who-may-do-what cannot hide inside a broad
# `go test ./...` log. Covers the JWT verifier (algorithm/claim/key-rotation
# attacks), the role table over the real route set, audit attribution, the
# /metrics token gate, and netrad's fail-fast OIDC config. The live-binary
# counterpart is scripts/ci-oidc-live.sh.
#
# Usage:
#   ./scripts/ci-auth-unit.sh
#   RACE=0 COUNT=3 ./scripts/ci-auth-unit.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RACE="${RACE:-1}"
COUNT="${COUNT:-1}"

RACE_FLAG=()
if [[ "$RACE" == "1" ]]; then
  RACE_FLAG=(-race)
fi

echo "==> oidcauth: JWT verification, JWKS rotation/back-off, role mapping"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./internal/oidcauth/...

echo "==> api: role ladder on real routes, spoof-proof audit actor, metrics gate, route-table integrity"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./internal/api/ \
  -run 'RBAC|OIDC|StaticKeys|IdPOutage|Whoami|DevMode|VerifiedActor|DeniedRequests|QueryString|MetricsTokenGate|AuthOrAgent|RoleTables|EveryMutating|RequiredRole'

echo "==> netrad: fail-fast OIDC config, OTLP push through a token-gated /metrics"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./cmd/netrad/ -run 'BuildOIDC|StartOTLPStillPushesWhenMetricsAreTokenGated'
