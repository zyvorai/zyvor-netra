// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Fleet-wide flow history (local plus NETRA_FLEET_PEERS) and the metric exporter status. Read-only.
struct CovFleetPage: View {
    enum Tab: String, CaseIterable, Identifiable { case flows = "Fleet flow history", exporters = "Metric exporters"; var id: String { rawValue } }
    @State private var tab = Tab.flows

    var body: some View {
        VStack(spacing: 0) {
            CovTabBar(tab: $tab)
            switch tab {
            case .flows: CovFleetFlows().id(tab)
            case .exporters: CovExporters().id(tab)
            }
        }
    }
}

private struct CovFleetFlows: View {
    @State private var since = "1h"
    @State private var limit = 200
    @State private var namespace = ""
    @State private var applied = ""

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("Since", selection: $since) { ForEach(["15m", "1h", "6h", "24h"], id: \.self) { Text($0).tag($0) } }.pickerStyle(.segmented).frame(maxWidth: 300)
                Picker("Limit", selection: $limit) { ForEach([100, 200, 500, 1000, 2000], id: \.self) { Text(String($0)).tag($0) } }.frame(maxWidth: 140)
                TextField("Namespace", text: $namespace).textFieldStyle(.roundedBorder).frame(maxWidth: 180).onSubmit { applied = namespace }
                Spacer()
            }.padding(.horizontal).padding(.vertical, 6)
            CovLoader(title: "Fleet flow history", endpoint: "api/v1/fleet/flows/history",
                      query: CoverageData.flowQuery(since: since, limit: limit, namespace: applied), liveEvery: nil) { json in
                let health = CoverageData.clusterHealth(json)
                VStack(spacing: 0) {
                    CovClusterStrip(clusters: DetectData.rows(json, "clusters")).padding(.horizontal).padding(.top, 6)
                    CovRowsView(json: json, rows: json.rows(at: "records", idKeys: ["peer", "pod"]), stats: [
                        .init(title: "Matched", symbol: "list.bullet") { String(CoverageData.int($0["matched"])) },
                        .init(title: "Clusters ok", symbol: "checkmark.circle", tint: .green) { _ in String(health.ok) },
                        .init(title: "Clusters failed", symbol: "xmark.circle", tint: .red) { _ in String(health.failed) },
                        .init(title: "Truncated", symbol: "scissors") { CoverageData.bool($0["truncated"]) ? "yes" : "no" },
                    ], columns: [
                        .init(title: "Observed", path: "observedAt", kind: .time), .init(title: "Node", path: "node"), .init(title: "Namespace", path: "namespace"),
                        .init(title: "Workload", path: "workloadName", width: 160), .init(title: "Pod", path: "pod", width: 160), .init(title: "Peer", path: "peer", width: 140),
                        .init(title: "Port", path: "port", kind: .int, width: 60), .init(title: "Proto", path: "protocol", width: 60), .init(title: "Dir", path: "direction", width: 70),
                        .init(title: "App", path: "appProtocol"), .init(title: "Packets", path: "packets", kind: .int), .init(title: "Bytes", path: "bytes", kind: .bytes),
                        .init(title: "Blocked", path: "blocked", kind: .int), .init(title: "Retrans", path: "retransmissions", kind: .int), .init(title: "Comm", path: "comm", width: 100),
                    ], empty: "No flow records match (history may be off, or retention shorter than the window).", notes: CoverageData.notes(json))
                }
            }
        }
    }
}

/// One chip per cluster: local or peer, reachable or not, and the peer's error when it failed.
private struct CovClusterStrip: View {
    let clusters: [JSONValue]
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(Array(clusters.enumerated()), id: \.offset) { _, c in
                    let ok = CoverageData.bool(c["ok"])
                    Label("\(c["name"]?.string ?? "cluster")\(CoverageData.bool(c["local"]) ? " (local)" : ""): \(ok ? "\(CoverageData.int(c["matched"])) records" : (c["error"]?.string ?? "failed"))",
                          systemImage: ok ? "checkmark.circle" : "xmark.octagon")
                        .font(.caption).foregroundStyle(ok ? Color.secondary : .red)
                        .padding(.horizontal, 8).padding(.vertical, 3).background(.quaternary, in: Capsule())
                }
            }
        }
    }
}

private struct CovExporters: View {
    var body: some View {
        CovLoader(title: "Metric exporters", endpoint: "api/v1/metrics/exporters", liveEvery: 10) { json in
            let t = CoverageData.exporterTotals(json)
            CovRowsView(json: json, rows: json.rows(at: "exporters", idKeys: ["sink"]), stats: [
                .init(title: "Sinks", symbol: "square.and.arrow.up") { String(DetectData.rows($0, "exporters").count) },
                .init(title: "Points sent", symbol: "chart.dots.scatter") { _ in String(t.sent) },
                .init(title: "Failures", symbol: "xmark.circle", tint: .red) { _ in String(t.failures) },
            ], columns: [
                .init(title: "Sink", path: "sink", width: 200), .init(title: "Resolution", path: "resolution", width: 90), .init(title: "Points sent", path: "pointsSent", kind: .int),
                .init(title: "Batches", path: "batches", kind: .int), .init(title: "Failures", path: "failures", kind: .int),
                .init(title: "Last send", path: "lastSend", kind: .time), .init(title: "Last error", path: "lastError", width: 320),
            ], empty: "No metric exporters are configured.")
        }
    }
}
