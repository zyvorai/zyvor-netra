// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Read-only process-level watches: capability, network-namespace and executable-hash drift, scan findings and the
/// auto-mitigate shadow preview. Exe paths and comm only; never argv or environment. Nothing here applies a rule.
struct CovProcessPage: View {
    enum Tab: String, CaseIterable, Identifiable {
        case caps = "Capabilities", namespaces = "Namespaces", exehash = "Executable hash", scans = "Scan findings", mitigate = "Auto-mitigate preview"
        var id: String { rawValue }
    }
    @State private var tab = Tab.caps

    var body: some View {
        VStack(spacing: 0) {
            CovTabBar(tab: $tab)
            content.id(tab)
        }
    }

    @ViewBuilder private var content: some View {
        switch tab {
        case .caps: CovDrift(title: "Capability changes", endpoint: "api/v1/ebpf/capdrift", rows: CoverageData.capEventRows, columns: [
            .init(title: "Workload", path: "workload", width: 200), .init(title: "PID", path: "pid", kind: .int, width: 70), .init(title: "Comm", path: "comm", width: 120),
            .init(title: "Exe", path: "exe", width: 220), .init(title: "Gained", path: "gained", width: 200), .init(title: "Lost", path: "lost", width: 160),
            .init(title: "Before", path: "previousHex", width: 90), .init(title: "After", path: "currentHex", width: 90),
        ])
        case .namespaces: CovDrift(title: "Namespace changes", endpoint: "api/v1/ebpf/nsdrift", rows: CoverageData.nsEventRows, columns: [
            .init(title: "Workload", path: "workload", width: 200), .init(title: "PID", path: "pid", kind: .int, width: 70), .init(title: "Comm", path: "comm", width: 120),
            .init(title: "Exe", path: "exe", width: 220), .init(title: "Net NS before", path: "previousNetNs", kind: .int, width: 110), .init(title: "Net NS after", path: "currentNetNs", kind: .int, width: 110),
        ])
        case .exehash: CovDrift(title: "Executable hash changes", endpoint: "api/v1/ebpf/exehash", rows: CoverageData.exeEventRows, columns: [
            .init(title: "Workload", path: "workload", width: 200), .init(title: "PID", path: "pid", kind: .int, width: 70), .init(title: "Comm", path: "comm", width: 120),
            .init(title: "Exe", path: "exe", width: 220), .init(title: "Before", path: "previousShort", width: 120), .init(title: "After", path: "currentShort", width: 120),
        ])
        case .scans: CovScanFindings()
        case .mitigate: CovMitigatePreview()
        }
    }
}

/// capdrift / nsdrift / exehash share one response shape: `anomalies[]` (severity, kind, subject, message) and `events[]`.
private struct CovDrift: View {
    let title: String
    let endpoint: String
    let rows: (JSONValue) -> [ControlRow]
    let columns: [PageColumn]
    var body: some View {
        CovLoader(title: title, endpoint: endpoint, query: [.init(name: "limit", value: "100")], liveEvery: 15) { json in
            let anomalies = DetectData.rows(json, "anomalies")
            VStack(spacing: 0) {
                if !anomalies.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(anomalies.prefix(5).enumerated()), id: \.offset) { _, a in
                            HStack(spacing: 8) {
                                DetectSeverityBadge(severity: a["severity"]?.string ?? "")
                                Text(a["subject"]?.string ?? "").font(.callout.weight(.medium))
                                Text(a["message"]?.string ?? "").font(.callout).foregroundStyle(.secondary).lineLimit(2)
                            }
                        }
                    }.padding(.horizontal).padding(.top, 8).frame(maxWidth: .infinity, alignment: .leading)
                }
                CovRowsView(json: json, rows: rows(json), stats: [
                    .init(title: "Events", symbol: "arrow.triangle.swap") { String(DetectData.rows($0, "events").count) },
                    .init(title: "Anomalies", symbol: "exclamationmark.triangle", tint: .orange) { String(DetectData.rows($0, "anomalies").count) },
                ], columns: columns, empty: "No changes observed. Needs process metadata on a node with socket owners.")
            }
        }
    }
}

private struct CovScanFindings: View {
    var body: some View {
        CovLoader(title: "Scan findings", endpoint: "api/v1/ebpf/scan-findings", liveEvery: 15) { json in
            let totals = CoverageData.findingTotals(json)
            CovRowsView(json: json, rows: json.rows(at: "findings", idKeys: ["id"]), stats: [
                .init(title: "Active findings", symbol: "binoculars", tint: .orange) { CoverageData.int($0.at("snapshot.activeFindings")).description },
                .init(title: "Workloads tracked", symbol: "shippingbox") { CoverageData.int($0.at("snapshot.workloadsTracked")).description },
                .init(title: "Attempts seen", symbol: "arrow.up.right") { CoverageData.int($0.at("snapshot.attemptsSeen")).description },
            ] + totals.map { t in PageStat(title: t.type, symbol: "number") { _ in String(t.count) } }, columns: [
                .init(title: "Severity", path: "severity", width: 80), .init(title: "Type", path: "type", width: 130), .init(title: "Score", path: "score", kind: .number(1), width: 60),
                .init(title: "Namespace", path: "namespace"), .init(title: "Pod", path: "pod", width: 160), .init(title: "Workload", path: "workload", width: 140),
                .init(title: "Node", path: "node"), .init(title: "Comm", path: "comm", width: 100),
                .init(title: "Dst IPs", path: "uniqueDstIps", kind: .int, width: 60), .init(title: "Dst ports", path: "uniqueDstPorts", kind: .int, width: 70),
                .init(title: "Attempts", path: "attempts", kind: .int), .init(title: "SYN only", path: "synOnly", kind: .int), .init(title: "Resets", path: "resets", kind: .int),
                .init(title: "Last seen", path: "lastSeen", kind: .time), .init(title: "Signals", path: "signals", width: 260),
            ], empty: "No scan, fan-out, lateral-movement or SYN-flood findings.")
        }
    }
}

private struct CovMitigatePreview: View {
    var body: some View {
        CovLoader(title: "Auto-mitigate preview", endpoint: "api/v1/ebpf/auto-mitigate/preview", liveEvery: 15) { json in
            let split = CoverageData.candidateSplit(json)
            VStack(spacing: 0) {
                Label("Shadow preview only. It applies nothing; actions still need enforce mode with an active lease.", systemImage: "eye")
                    .font(.callout).foregroundStyle(.secondary).padding(8).frame(maxWidth: .infinity, alignment: .leading)
                if !CoverageData.bool(json["enabled"]) {
                    Label("Auto-mitigate is not enabled on this controller (set NETRA_AUTOMITIGATE_ENABLED=true to preview candidates).", systemImage: "power.dotted")
                        .font(.callout).foregroundStyle(.orange).padding(.horizontal, 8).frame(maxWidth: .infinity, alignment: .leading)
                }
                CovRowsView(json: json, rows: json.rows(at: "candidates", idKeys: ["findingId", "target"]), stats: [
                    .init(title: "Enabled", symbol: "power") { CoverageData.bool($0["enabled"]) ? "yes" : "no" },
                    .init(title: "Lease active", symbol: "timer") { CoverageData.bool($0["leaseActive"]) ? "yes" : "no" },
                    .init(title: "Mode", symbol: "switch.2") { $0["mode"]?.summary ?? "" },
                    .init(title: "Would act", symbol: "bolt", tint: .orange) { _ in String(split.wouldAct) },
                    .init(title: "Skipped", symbol: "forward") { _ in String(split.skipped) },
                    .init(title: "Cooldown skips", symbol: "hourglass") { String(CoverageData.int($0["skippedRecent"])) },
                ], columns: [
                    .init(title: "Kind", path: "kind", width: 110), .init(title: "Target", path: "target", width: 220), .init(title: "Finding", path: "findingId", width: 160),
                    .init(title: "Detail", path: "detail", width: 280), .init(title: "Skipped because", path: "skipped", width: 220),
                ], empty: "No candidates right now.", notes: CoverageData.notes(json))
            }
        }
    }
}
