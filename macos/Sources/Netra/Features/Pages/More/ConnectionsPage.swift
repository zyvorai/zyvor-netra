// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Native connections. The web page has no /ebpf/connections endpoint: it reads the sampled events each agent
/// reports in GET /api/v1/agents ({items:[{node,stale,events:[{observedAt,sourceIp,sourcePort,destinationIp,
/// destinationPort,protocol,direction,hook,action,reason,comm,namespace,pod,dnsQuery}]}]}). Read-only.
struct MoreConnectionsPage: View {
    var body: some View {
        MoreLoader(title: "Connections", endpoint: "api/v1/agents", liveEvery: 10) { v, _ in
            let rows = MoreData.agentEvents(v)
            let s = MoreData.eventStats(rows)
            VStack(spacing: 0) {
                StatRow(stats: [
                    .init(title: "Sampled events", symbol: "link") { _ in String(s.total) },
                    .init(title: "Blocked", symbol: "xmark.octagon", tint: .red) { _ in String(s.blocked) },
                    .init(title: "Workloads", symbol: "shippingbox") { _ in String(s.workloads) },
                    .init(title: "Nodes", symbol: "server.rack") { _ in String(s.nodes) },
                ], value: v).padding([.horizontal, .top])
                Text("Recent sampled events reported by Netra agents. Not a full connection table.")
                    .font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal)
                MoreRowsTable(rows: rows, columns: [
                    .init(title: "When", path: "observedAt", kind: .time, width: 80), .init(title: "Node", path: "node", width: 100),
                    .init(title: "Workload", path: "workload", width: 150), .init(title: "Source", path: "src", width: 140),
                    .init(title: "Destination", path: "dst", width: 150), .init(title: "Proto", path: "protocol", width: 55),
                    .init(title: "Dir", path: "direction", width: 60), .init(title: "Action", path: "action", width: 70),
                    .init(title: "Reason", path: "reason", width: 110), .init(title: "Process", path: "comm", width: 90),
                ], empty: "No sampled events in the agents' latest reports.")
            }
        }
    }
}
