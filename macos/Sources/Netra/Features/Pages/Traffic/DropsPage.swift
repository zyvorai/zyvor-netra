// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Drops: kernel skb drop reasons, drop sites and tuples, and a read-only explainer. All GETs.
struct DropsPage: View {
    enum Tab: String, CaseIterable { case overview = "Overview", reasons = "Reasons", sites = "Sites", flows = "Flows", explain = "Explain" }
    @State private var tab: Tab = .overview

    var body: some View {
        VStack(spacing: 0) {
            TrafficTabs(selection: $tab)
            switch tab {
            case .overview: overview
            case .reasons: reasons
            case .sites: sites
            case .flows: flows
            case .explain: explain
            }
        }
    }

    // GET /api/v1/ebpf/drops: summary + nodes[].kernelDrops. Rows are the server's anomalies.
    private var overview: some View {
        DataPageView(PageConfig(
            title: "Drops", endpoint: "api/v1/ebpf/drops", query: [.init(name: "limit", value: "100")],
            rowsPath: "summary.anomalies", idKeys: ["subject", "kind"],
            columns: [
                .init(title: "Severity", path: "severity", width: 80),
                .init(title: "Kind", path: "kind", width: 120),
                .init(title: "Subject", path: "subject", width: 120),
                .init(title: "Message", path: "message", width: 300),
                .init(title: "Value", path: "value", kind: .int, width: 70),
            ],
            stats: [
                .init(title: "Kernel skb drops", symbol: "arrow.down.right.and.arrow.up.left.slash.circle", tint: .red) { CellFormat.text($0.at("summary.kernelDropEvents") ?? .number(0), .int) },
                .init(title: "Softnet dropped", symbol: "tray.full", tint: .orange) { CellFormat.text($0.at("summary.softnetDropped") ?? .number(0), .int) },
                .init(title: "Time squeeze", symbol: "timer", tint: .orange) { CellFormat.text($0.at("summary.softnetTimeSqueeze") ?? .number(0), .int) },
                .init(title: "RX / TX dropped", symbol: "network") { v in
                    "\(CellFormat.text(v.at("summary.rxDropped") ?? .number(0), .int)) / \(CellFormat.text(v.at("summary.txDropped") ?? .number(0), .int))" },
                .init(title: "Qdisc drops", symbol: "line.3.horizontal.decrease") { CellFormat.text($0.at("summary.qdiscDrops") ?? .number(0), .int) },
                .init(title: "RX/TX errors", symbol: "exclamationmark.triangle", tint: .orange) { v in
                    "\(CellFormat.text(v.at("summary.rxErrors") ?? .number(0), .int)) / \(CellFormat.text(v.at("summary.txErrors") ?? .number(0), .int))" },
                .init(title: "Anomalies", symbol: "waveform.path.ecg", tint: .orange) { String($0.rows(at: "summary.anomalies").count) },
            ],
            liveEvery: 5, emptyText: "No drop anomalies: nothing is going missing."
        )) { v in
            RankedBarsCard(title: "Kernel drop reasons (all nodes, since attach)", bars: TrafficData.kernelReasonBars(v), unit: "drops")
        }
    }

    // GET /api/v1/ebpf/drop-info: reasons[], sites[], flows[], totals, nodes[].
    private func dropInfo(title: String, rows: String, columns: [PageColumn], empty: String, chart: Bool = false) -> some View {
        DataPageView(PageConfig(
            title: title, endpoint: "api/v1/ebpf/drop-info", query: [.init(name: "top", value: "100")],
            rowsPath: rows, idKeys: ["reason", "location", "dst"], columns: columns,
            stats: [
                .init(title: "Drops", symbol: "arrow.down.right.and.arrow.up.left.slash.circle", tint: .red) { CellFormat.text($0.at("totals.drops") ?? .number(0), .int) },
                .init(title: "With tuple", symbol: "number") { CellFormat.text($0.at("totals.withTuple") ?? .number(0), .int) },
                .init(title: "Read errors", symbol: "exclamationmark.triangle", tint: .orange) { CellFormat.text($0.at("totals.readErrors") ?? .number(0), .int) },
                .init(title: "Nodes reporting", symbol: "server.rack", tint: .green) { CellFormat.text($0.at("nodesReporting") ?? .number(0), .int) },
                .init(title: "Not reporting", symbol: "eye.slash", tint: .orange) { CellFormat.text($0.at("nodesNotReporting") ?? .number(0), .int) },
            ],
            liveEvery: 5, emptyText: empty
        )) { v in
            if chart {
                RankedBarsCard(title: "Drops by reason", bars: TrafficData.rankedBars(v, at: "reasons", valueKey: "count") { $0["reason"]?.string }, unit: "drops")
            }
        }
    }

    private var reasons: some View {
        dropInfo(title: "Drop reasons", rows: "reasons", columns: [
            .init(title: "Reason", path: "reason", width: 220), .init(title: "Count", path: "count", kind: .int, width: 100),
        ], empty: "No kernel drop reasons reported (sensor needs kernel BTF and tracefs).", chart: true)
    }

    private var sites: some View {
        dropInfo(title: "Drop sites", rows: "sites", columns: [
            .init(title: "Reason", path: "reason", width: 160), .init(title: "Kernel function", path: "location", width: 240), .init(title: "Count", path: "count", kind: .int, width: 100),
        ], empty: "No drop sites reported.")
    }

    private var flows: some View {
        dropInfo(title: "Dropped flows", rows: "flows", columns: [
            .init(title: "Node", path: "node", width: 100), .init(title: "Proto", path: "proto", width: 60),
            .init(title: "Source", path: "src", width: 130), .init(title: "Src port", path: "srcPort", kind: .int, width: 70),
            .init(title: "Destination", path: "dst", width: 130), .init(title: "Dst port", path: "dstPort", kind: .int, width: 70),
            .init(title: "Reason", path: "reason", width: 140), .init(title: "Count", path: "count", kind: .int, width: 80),
            .init(title: "Function", path: "location", width: 160),
        ], empty: "No dropped flows with a readable IP header.")
    }

    // GET /api/v1/drops/explain: unified findings (Netra policy drops, optional Hubble).
    private var explain: some View {
        DataPageView(PageConfig(
            title: "Explain drops", endpoint: "api/v1/drops/explain", query: [.init(name: "limit", value: "50")],
            rowsPath: "findings", idKeys: ["code", "src"],
            columns: [
                .init(title: "Confidence", path: "confidence", width: 90), .init(title: "Source", path: "source", width: 70),
                .init(title: "Code", path: "code", width: 170), .init(title: "Node", path: "node", width: 90),
                .init(title: "Src", path: "src", width: 130), .init(title: "Dst", path: "dst", width: 130),
                .init(title: "Packets", path: "packets", kind: .int, width: 70),
                .init(title: "Why", path: "explanation", width: 320), .init(title: "Suggestion", path: "suggestion", width: 320),
            ],
            stats: [
                .init(title: "Policy-drop packets", symbol: "shield.slash", tint: .red) { CellFormat.text($0.at("summary.policyDropPackets") ?? .number(0), .int) },
                .init(title: "Policy-drop flows", symbol: "arrow.triangle.branch") { CellFormat.text($0.at("summary.policyDropFlows") ?? .number(0), .int) },
                .init(title: "Exact findings", symbol: "exclamationmark.octagon.fill", tint: .red) { CellFormat.text($0.at("summary.exactFindings") ?? .number(0), .int) },
                .init(title: "Probable", symbol: "exclamationmark.triangle.fill", tint: .orange) { CellFormat.text($0.at("summary.probableFindings") ?? .number(0), .int) },
                .init(title: "Conntrack entries", symbol: "link") { CellFormat.text($0.at("summary.conntrackEntries") ?? .number(0), .int) },
            ],
            liveEvery: 10, emptyText: "No drops to explain."
        )) { v in
            if let t = v.at("summary.text")?.string, !t.isEmpty {
                Label(t, systemImage: "text.magnifyingglass").font(.callout).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal).padding(.bottom, 8)
            }
        }
    }
}
