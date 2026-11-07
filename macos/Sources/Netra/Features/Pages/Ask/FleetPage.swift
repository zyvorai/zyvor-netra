// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Per-node fleet table from GET /api/v1/fleet (observe-only). The server reports no agent version
/// field, so none is shown. Peer clusters (NETRA_FLEET_PEERS) come from GET /api/v1/fleet/clusters.
struct FleetPage: View {
    private let config = PageConfig(
        title: "Fleet", endpoint: "api/v1/fleet", rowsPath: "nodes", idKeys: ["node"],
        columns: [
            PageColumn(title: "Node", path: "node", width: 140),
            PageColumn(title: "Mode", path: "mode"),
            PageColumn(title: "Stale", path: "stale", kind: .bool),
            PageColumn(title: "Last seen", path: "ageSeconds", kind: .seconds),
            PageColumn(title: "Observed", path: "observedAt", kind: .time),
            PageColumn(title: "Programs", path: "programs", kind: .int),
            PageColumn(title: "Attached", path: "attached", kind: .int),
            PageColumn(title: "Hooks", path: "hooks", kind: .int),
            PageColumn(title: "Workloads", path: "workloads", kind: .int),
            PageColumn(title: "Destinations", path: "destinations", kind: .int),
            PageColumn(title: "Events", path: "events", kind: .int),
            PageColumn(title: "CPU", path: "cpuPercent", kind: .percent),
            PageColumn(title: "Mem used", path: "memoryUsedBytes", kind: .bytes),
            PageColumn(title: "Load 1m", path: "loadAvg1", kind: .number(2)),
        ],
        stats: [
            PageStat(title: "Nodes", symbol: "server.rack") { AskData.fleetSummary($0).nodes.description },
            PageStat(title: "Stale", symbol: "clock.badge.exclamationmark", tint: .orange) { AskData.fleetSummary($0).stale.description },
            PageStat(title: "Healthy", symbol: "checkmark.seal", tint: .green) {
                let s = AskData.fleetSummary($0); return s.nodes == 0 ? "" : String(format: "%.0f%%", s.healthyFraction * 100)
            },
            PageStat(title: "Workloads", symbol: "shippingbox") { AskData.fleetSummary($0).workloads.description },
        ],
        emptyText: "No node agents are reporting.")

    var body: some View { DataPageView(config) { _ in ClusterStrip() } }
}

private struct ClusterStrip: View {
    @Environment(AppModel.self) private var model
    @State private var clusters: [ControlRow] = []
    var body: some View {
        Group {
            if clusters.count > 1 || clusters.contains(where: { !$0.value.at("local").isTrue }) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        ForEach(clusters) { c in
                            let h = AskData.clusterHealth(c.value)
                            VStack(alignment: .leading, spacing: 3) {
                                HStack { Image(systemName: "circle.fill").font(.caption2).foregroundStyle(h == "ok" ? .green : h == "unreachable" ? .red : .orange)
                                    Text(c.value.at("name")?.summary ?? "cluster").font(.callout.weight(.semibold)) }
                                Text("\(h) · \(c.value.at("agentCount")?.summary ?? "0") agents" + (c.value.at("tenant") != nil ? " · \(c.value.at("tenant")!.summary)" : ""))
                                    .font(.caption).foregroundStyle(.secondary)
                                if let e = c.value.at("error")?.string, !e.isEmpty { Text(e).font(.caption2).foregroundStyle(.red).lineLimit(1) }
                            }
                            .padding(8).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
                            .accessibilityElement(children: .combine)
                        }
                    }.padding(.horizontal).padding(.bottom, 8)
                }
            }
        }
        .task {
            guard let c = model.client else { return }
            if let d = try? await c.send(c.request("GET", "api/v1/fleet/clusters")), let v = try? JSONDecoder().decode(JSONValue.self, from: d) {
                clusters = v.rows(at: "clusters", idKeys: ["name"])
            }
        }
    }
}

private extension Optional where Wrapped == JSONValue {
    var isTrue: Bool { if case .bool(true)? = self { true } else { false } }
}
