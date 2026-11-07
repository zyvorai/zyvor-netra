// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// TCP events (read-only). GET /api/v1/ebpf/tcp-events?top=N:
/// {nodes:[{node,sensors,skipped,reporting}], nodesReporting, nodesNotReporting,
///  totals:{retransmits,rstSent,rstReceived,stateTransitions,readErrors,badFamily,mapFull},
///  transitions:[{from,to,count}], flows:[{node,family,src,dst,srcPort,dstPort,retransmits,rstSent,rstReceived,lastSeenNs}]}
struct MoreTCPEventsPage: View {
    enum Tab: String, CaseIterable { case flows = "Flows", transitions = "State transitions", nodes = "Nodes" }
    @State private var tab: Tab = .flows

    var body: some View {
        VStack(spacing: 0) {
            TrafficTabs(selection: $tab)
            switch tab {
            case .flows: flows
            case .transitions: transitions
            case .nodes: nodes
            }
        }
    }

    private var stats: [PageStat] {
        func n(_ k: String) -> (JSONValue) -> String { { TrafficData.compact($0.at("totals.\(k)")?.asDouble ?? 0) } }
        return [
            .init(title: "Retransmits", symbol: "arrow.triangle.2.circlepath", tint: .orange, value: n("retransmits")),
            .init(title: "RST sent", symbol: "xmark.circle", tint: .red, value: n("rstSent")),
            .init(title: "RST received", symbol: "xmark.circle.fill", tint: .red, value: n("rstReceived")),
            .init(title: "State changes", symbol: "arrow.left.arrow.right", value: n("stateTransitions")),
            .init(title: "Nodes reporting", symbol: "server.rack", tint: .green) { v in
                "\(Int(v.at("nodesReporting")?.asDouble ?? 0)) / \(Int(v.at("nodesReporting")?.asDouble ?? 0) + Int(v.at("nodesNotReporting")?.asDouble ?? 0))" },
        ]
    }

    @ViewBuilder private func warnings(_ v: JSONValue) -> some View {
        if let w = MoreData.tcpUndercountWarning(v) { MoreBanner(text: w) }
        let silent = MoreData.tcpSilentNodes(v)
        if !silent.isEmpty { MoreBanner(text: "No TCP event sensor on: \(silent.joined(separator: ", ")). Silence from these nodes is not evidence of a healthy network.", symbol: "eye.slash", tint: .secondary) }
    }

    private var flows: some View {
        DataPageView(PageConfig(
            title: "TCP events", endpoint: "api/v1/ebpf/tcp-events", query: [.init(name: "top", value: "200")],
            rowsPath: "flows", idKeys: ["src", "dst"],
            columns: [
                .init(title: "Node", path: "node", width: 110), .init(title: "Source", path: "src", width: 130), .init(title: "Port", path: "srcPort", kind: .int, width: 55),
                .init(title: "Destination", path: "dst", width: 130), .init(title: "Port", path: "dstPort", kind: .int, width: 55),
                .init(title: "Retrans", path: "retransmits", kind: .int, width: 70), .init(title: "RST sent", path: "rstSent", kind: .int, width: 70),
                .init(title: "RST recv", path: "rstReceived", kind: .int, width: 70),
            ],
            stats: stats, liveEvery: 10,
            emptyText: "No retransmits or resets recorded. Counts are since each node's sensor attached."
        )) { warnings($0) }
    }

    private var transitions: some View {
        DataPageView(PageConfig(
            title: "TCP state transitions", endpoint: "api/v1/ebpf/tcp-events", query: [.init(name: "top", value: "1")],
            rowsPath: "transitions", idKeys: ["from", "to"],
            columns: [.init(title: "From", path: "from", width: 120), .init(title: "To", path: "to", width: 120), .init(title: "Count", path: "count", kind: .int, width: 90)],
            stats: stats, liveEvery: 10, emptyText: "No state transitions recorded."
        )) { warnings($0) }
    }

    private var nodes: some View {
        MoreLoader(title: "TCP event sensors", endpoint: "api/v1/ebpf/tcp-events", query: [.init(name: "top", value: "1")], liveEvery: 10) { v, _ in
            VStack(spacing: 0) {
                warnings(v)
                MoreRowsTable(rows: MoreData.joined(MoreData.joined(v.rows(at: "nodes", idKeys: ["node"]), key: "sensors"), key: "skipped"),
                              columns: [.init(title: "Node", path: "node", width: 140), .init(title: "Reporting", path: "reporting", kind: .bool, width: 80),
                                        .init(title: "Sensors", path: "sensorsText", width: 260), .init(title: "Skipped", path: "skippedText", width: 260)],
                              empty: "No fresh agents.")
            }
        }
    }
}
