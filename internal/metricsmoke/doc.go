// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package metricsmoke holds the agent-side driver for
// scripts/ci-metrics-veth.sh: the real host collectors, anomaly detector and
// stream sender, without the eBPF datapath. It only builds with
// -tags=metricsveth.
package metricsmoke
