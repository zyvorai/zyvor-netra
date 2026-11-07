// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// Read-only datapath detail: drop reasons, deny/allow census, softirq and listen-queue histograms, the per-node
/// kernel-network sparkline and L7 observed at OpenSSL. Nothing here changes a tunable or a rule.
struct CovDatapathPage: View {
    enum Tab: String, CaseIterable, Identifiable {
        case reasons = "Drop reasons", census = "Deny census", stacks = "Stack histograms", sparkline = "Kernel sparkline", tls = "L7 over TLS"
        var id: String { rawValue }
    }
    @State private var tab = Tab.reasons

    var body: some View {
        VStack(spacing: 0) {
            CovTabBar(tab: $tab)
            content.id(tab)
        }
    }

    @ViewBuilder private var content: some View {
        switch tab {
        case .reasons: CovReasons()
        case .census: CovCensus()
        case .stacks: CovStacks()
        case .sparkline: CovSparkline()
        case .tls: CovTLSSample()
        }
    }
}

private struct CovReasons: View {
    var body: some View {
        CovLoader(title: "Drop reasons", endpoint: "api/v1/ebpf/reasons", liveEvery: 10) { json in
            CovRowsView(json: json, rows: json.rows(at: "buckets", idKeys: ["reason", "action"]), stats: [
                .init(title: "Total", symbol: "sum") { String(CoverageData.int($0["total"])) },
                .init(title: "Blocked", symbol: "hand.raised", tint: .red) { String(CoverageData.int($0["blocked"])) },
            ], columns: [
                .init(title: "Action", path: "action", width: 100), .init(title: "Reason", path: "reason", width: 280), .init(title: "Count", path: "count", kind: .int),
            ], empty: "No drop or block reasons recorded.")
        }
    }
}

private struct CovCensus: View {
    var body: some View {
        CovLoader(title: "Deny census", endpoint: "api/v1/ebpf/census", liveEvery: 15) { json in
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    StatRow(stats: [
                        .init(title: "Mode", symbol: "switch.2") { $0["mode"]?.summary ?? "" },
                        .init(title: "Denied entries", symbol: "hand.raised", tint: .red) { String(CoverageData.int($0["totalDenied"])) },
                        .init(title: "Allowed entries", symbol: "checkmark.shield", tint: .green) { String(CoverageData.int($0["totalAllowed"])) },
                    ], value: json)
                    HStack(alignment: .top, spacing: 14) {
                        ForEach(CoverageData.censusGroups(json), id: \.title) { g in KVSection(title: g.title, items: g.items) }
                    }
                    Text("Counts of programmed entries, not traffic.").font(.caption).foregroundStyle(.secondary)
                }.padding()
            }
        }
    }
}

private struct CovStacks: View {
    var body: some View {
        CovLoader(title: "Stack histograms", endpoint: "api/v1/ebpf/stack-histograms", liveEvery: 15) { json in
            let nodes = DetectData.rows(json, "nodes")
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    CovNotes(lines: CoverageData.notes(json))
                    if nodes.isEmpty { ContentUnavailableView("No fresh agent reports", systemImage: "tray") }
                    ForEach(Array(nodes.enumerated()), id: \.offset) { _, n in
                        GroupBox(n["node"]?.string ?? "node") {
                            VStack(alignment: .leading, spacing: 10) {
                                HStack(spacing: 10) {
                                    StatCard(title: "Softirq NET_RX", value: String(CoverageData.int(n["softirqNetRx"])), symbol: "arrow.down.circle")
                                    StatCard(title: "Softnet dropped", value: String(CoverageData.int(n["softnetDropped"])), symbol: "arrow.down.right.circle", tint: .red)
                                    StatCard(title: "Time squeeze", value: String(CoverageData.int(n["softnetTimeSqueeze"])), symbol: "gauge.with.dots.needle.100percent", tint: .orange)
                                    StatCard(title: "Listen overflows", value: String(CoverageData.int(n["listenOverflows"])), symbol: "tray.full", tint: .orange)
                                    StatCard(title: "Listen drops", value: String(CoverageData.int(n["listenDrops"])), symbol: "tray.full.fill", tint: .red)
                                }
                                let b = CoverageData.depthBuckets(n)
                                if !b.isEmpty {
                                    Text("Listen queue depth (sockets per bucket)").font(.caption).foregroundStyle(.secondary)
                                    Chart(b, id: \.label) { BarMark(x: .value("Depth", $0.label), y: .value("Sockets", $0.count)) }
                                        .frame(height: 110).accessibilityLabel("Listen queue depth buckets for \(n["node"]?.string ?? "node")")
                                }
                                let top = DetectData.rows(n, "topListeners")
                                if !top.isEmpty {
                                    Text("Top listeners").font(.caption).foregroundStyle(.secondary)
                                    ForEach(Array(top.prefix(5).enumerated()), id: \.offset) { _, l in
                                        Text(l.summaryLine).font(.caption.monospaced()).lineLimit(1)
                                    }
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }.padding()
            }
        }
    }
}

private extension JSONValue {
    /// One compact "key=value" line of an object's scalar fields (for listener rows whose shape is the agent's).
    var summaryLine: String {
        guard case .object(let o) = self else { return summary }
        return o.keys.sorted().compactMap { k in o[k].map { "\(k)=\($0.summary)" } }.joined(separator: "  ")
    }
}

private struct CovSparkline: View {
    @Environment(AppModel.self) private var model
    @State private var nodes: [String] = []
    @State private var node = ""
    @State private var points = 30
    @State private var field = CoverageData.sparklineFields[0].field

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("Node", selection: $node) { Text("Choose a node").tag(""); ForEach(nodes, id: \.self) { Text($0).tag($0) } }.frame(maxWidth: 300)
                Picker("Series", selection: $field) { ForEach(CoverageData.sparklineFields, id: \.field) { Text($0.title).tag($0.field) } }.frame(maxWidth: 280)
                Stepper("Points: \(points)", value: $points, in: 5...60, step: 5)
                Spacer()
            }.padding(8)
            Divider()
            if node.isEmpty {
                ContentUnavailableView("Pick a node", systemImage: "waveform.path.ecg", description: Text("Recent kernel-network windows for one node: softnet, NIC and qdisc drop rates."))
            } else {
                CovLoader(title: "Kernel sparkline", endpoint: "api/v1/ebpf/kernel-network/sparkline",
                          query: [.init(name: "node", value: node), .init(name: "points", value: String(points))], liveEvery: 15) { json in
                    let series = CoverageData.sparkline(json, field: field)
                    let title = CoverageData.sparklineFields.first { $0.field == field }?.title ?? field
                    VStack(alignment: .leading, spacing: 10) {
                        if series.isEmpty {
                            ContentUnavailableView("No windows yet", systemImage: "hourglass", description: Text("The controller has not accumulated kernel-network windows for \(node)."))
                        } else {
                            Chart(series, id: \.at) { LineMark(x: .value("Time", $0.at), y: .value(title, $0.value)); PointMark(x: .value("Time", $0.at), y: .value(title, $0.value)) }
                                .frame(minHeight: 200).padding()
                                .accessibilityLabel("\(title) for \(node), \(series.count) windows")
                        }
                        CovTable(rows: json.rows(at: "windows", idKeys: ["endAt"]), columns: [
                            .init(title: "End", path: "endAt", kind: .time), .init(title: "Seconds", path: "seconds", kind: .number(0), width: 70),
                            .init(title: "Warming", path: "warming", kind: .bool, width: 70), .init(title: "Reset", path: "resetDetected", kind: .bool, width: 60),
                            .init(title: "Softnet drop /s", path: "softnetDroppedPerSecond", kind: .number(2)), .init(title: "Squeeze /s", path: "softnetTimeSqueezePerSecond", kind: .number(2)),
                            .init(title: "RX drop /s", path: "rxDroppedPerSecond", kind: .number(2)), .init(title: "TX drop /s", path: "txDroppedPerSecond", kind: .number(2)),
                            .init(title: "RX missed /s", path: "rxMissedPerSecond", kind: .number(2)), .init(title: "Qdisc /s", path: "qdiscDropsPerSecond", kind: .number(2)),
                        ], empty: "No windows.")
                    }
                }.id(node + String(points))
            }
        }
        .task {
            guard let c = model.client else { return }
            if case .success(let v) = await CovFetch.get(c, "api/v1/agents", feature: "Agents") {
                nodes = CoverageData.nodeNames(v)
                if node.isEmpty, nodes.count == 1 { node = nodes[0] }
            }
        }
    }
}

private struct CovTLSSample: View {
    enum Sub: String, CaseIterable, Identifiable { case protocols = "Protocols", hosts = "Hosts", nodes = "Nodes"; var id: String { rawValue } }
    @State private var sub = Sub.protocols

    var body: some View {
        CovLoader(title: "L7 over TLS", endpoint: "api/v1/l7/tls", liveEvery: 15) { json in
            VStack(spacing: 0) {
                StatRow(stats: [
                    .init(title: "Nodes reporting", symbol: "checkmark.circle", tint: .green) { String(CoverageData.int($0["nodesReporting"])) },
                    .init(title: "Not reporting", symbol: "xmark.circle", tint: .orange) { String(CoverageData.int($0["nodesNotReporting"])) },
                    .init(title: "Eligible", symbol: "list.number") { String(CoverageData.int($0["eligible"])) },
                    .init(title: "Emitted", symbol: "arrow.up.right") { String(CoverageData.int($0["emitted"])) },
                    .init(title: "Scale factor", symbol: "multiply") { $0["scaleFactor"]?.asDouble.map { String(format: "%.2f", $0) } ?? "" },
                ], value: json).padding([.horizontal, .top])
                CovNotes(lines: ["Sampled plaintext observed at OpenSSL for application protocols; counts are estimates scaled by the sampling factor. No payloads are shown."])
                Picker("View", selection: $sub) { ForEach(Sub.allCases) { Text($0.rawValue).tag($0) } }.pickerStyle(.segmented).frame(maxWidth: 320).padding(.horizontal).padding(.bottom, 6)
                switch sub {
                case .protocols:
                    CovTable(rows: json.rows(at: "protocols", idKeys: ["protocol", "role"]).map { r in
                        ControlRow(id: r.id, value: CoverageDataBridge.withErrorRatio(r.value))
                    }, columns: [
                        .init(title: "Protocol", path: "protocol", width: 110), .init(title: "Role", path: "role", width: 70), .init(title: "Requests", path: "requests", kind: .int),
                        .init(title: "Responses", path: "responses", kind: .int), .init(title: "Errors", path: "errors", kind: .int), .init(title: "Error ratio", path: "errorRatio", kind: .ratio),
                        .init(title: "Estimated", path: "estimatedRequests", kind: .number(0)), .init(title: "gRPC", path: "grpc", kind: .int), .init(title: "Undecodable", path: "undecodable", kind: .int),
                    ], empty: "No TLS plaintext protocols observed.")
                case .hosts:
                    CovTable(rows: json.rows(at: "hosts", idKeys: ["host", "op"]), columns: [
                        .init(title: "Role", path: "role", width: 70), .init(title: "Host", path: "host", width: 260), .init(title: "Op", path: "op", width: 100), .init(title: "Count", path: "count", kind: .int),
                    ], empty: "No hosts observed.")
                case .nodes:
                    CovTable(rows: json.rows(at: "nodes", idKeys: ["node"]), columns: [
                        .init(title: "Node", path: "node", width: 160), .init(title: "Reporting", path: "reporting", kind: .bool, width: 80),
                        .init(title: "Unavailable because", path: "unavailable", width: 280), .init(title: "Libraries", path: "libraries", width: 320),
                    ], empty: "No nodes.")
                }
            }
        }
    }
}

/// Adds the derived `errorRatio` to a sampled protocol row.
private enum CoverageDataBridge {
    static func withErrorRatio(_ row: JSONValue) -> JSONValue {
        guard case .object(var o) = row, let r = CoverageData.errorRatio(row) else { return row }
        o["errorRatio"] = .number(r)
        return .object(o)
    }
}
