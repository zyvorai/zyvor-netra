// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Path diagnostics (read-only). GET /api/v1/ebpf/path?limit=N:
/// {summary:{connectionsMeasured,averageConnectUs,maxConnectUs,pressureFlows,congestedFlows,packetsOut,retransOut,lostOut,
///  totalRetrans,deliveredRatePps,anomalies:[{severity,kind,subject,message}]},
///  pressure:[{remoteIp,remotePort,namespace,pod,sendCwnd,packetsOut,retransOut,lostOut,totalRetrans,rateDelivered,rateIntervalUs,mss}],
///  connect:[{remoteIp,remotePort,namespace,pod,established,totalLatencyUs,maxLatencyUs}], edgeIntel:{counts:{...}}}
struct MorePathPage: View {
    enum Tab: String, CaseIterable { case signals = "Signals", pressure = "TCP pressure", connect = "Connect latency" }
    @State private var tab: Tab = .signals
    private let query: [URLQueryItem] = [.init(name: "limit", value: "100")]

    var body: some View {
        MoreLoader(title: "Path & ICMP", endpoint: "api/v1/ebpf/path", query: query, liveEvery: 5) { v, _ in
            VStack(spacing: 0) {
                StatRow(stats: stats, value: v).padding([.horizontal, .top])
                TrafficTabs(selection: $tab)
                switch tab {
                case .signals: signals(v)
                case .pressure:
                    MoreRowsTable(rows: MoreData.pathRows(v, at: "pressure"), columns: [
                        .init(title: "Workload", path: "workload", width: 160), .init(title: "Remote", path: "remote", width: 150),
                        .init(title: "Cwnd use", path: "cwndRatio", kind: .ratio, width: 80), .init(title: "In flight", path: "packetsOut", kind: .int, width: 75),
                        .init(title: "Cwnd", path: "sendCwnd", kind: .int, width: 60), .init(title: "Lost", path: "lostOut", kind: .int, width: 55),
                        .init(title: "Retrans out", path: "retransOut", kind: .int, width: 85), .init(title: "Total retrans", path: "totalRetrans", kind: .int, width: 90),
                        .init(title: "MSS", path: "mss", kind: .int, width: 55),
                    ], empty: "No TCP pressure samples yet.")
                case .connect:
                    MoreRowsTable(rows: MoreData.pathRows(v, at: "connect"), columns: [
                        .init(title: "Workload", path: "workload", width: 160), .init(title: "Remote", path: "remote", width: 150),
                        .init(title: "Established", path: "established", kind: .int, width: 85), .init(title: "Avg (us)", path: "avgConnectUs", kind: .int, width: 80),
                        .init(title: "Max (us)", path: "maxLatencyUs", kind: .int, width: 80),
                    ], empty: "No TCP connect samples yet.")
                }
            }
        }
    }

    private var stats: [PageStat] {
        func n(_ k: String) -> (JSONValue) -> String { { TrafficData.compact($0.at("summary.\(k)")?.asDouble ?? 0) } }
        return [
            .init(title: "Connects timed", symbol: "timer", value: n("connectionsMeasured")),
            .init(title: "Avg connect", symbol: "gauge.medium") { MoreData.micros($0.at("summary.averageConnectUs")?.asDouble ?? 0) },
            .init(title: "Max connect", symbol: "gauge.high", tint: .orange) { MoreData.micros($0.at("summary.maxConnectUs")?.asDouble ?? 0) },
            .init(title: "Cwnd-pressure flows", symbol: "exclamationmark.triangle", tint: .orange, value: n("congestedFlows")),
            .init(title: "Retrans / lost out", symbol: "arrow.triangle.2.circlepath", tint: .red) { v in
                "\(TrafficData.compact(v.at("summary.retransOut")?.asDouble ?? 0)) / \(TrafficData.compact(v.at("summary.lostOut")?.asDouble ?? 0))" },
            .init(title: "Packets in flight", symbol: "shippingbox", value: n("packetsOut")),
        ]
    }

    private func signals(_ v: JSONValue) -> some View {
        let anomalies = v.rows(at: "summary.anomalies", idKeys: ["kind", "subject"])
        let counts = v.rows(at: "edgeIntel.counts").isEmpty ? v.mapRows(at: "edgeIntel.counts") : []
        return ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                GroupBox("Transport-pressure findings") {
                    if anomalies.isEmpty { KernelEmpty(text: "No path-pressure thresholds triggered.", symbol: "checkmark.circle") }
                    else {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(anomalies) { a in
                                HStack(alignment: .firstTextBaseline, spacing: 10) {
                                    MoreLevel(text: a.value["severity"]?.string ?? "").frame(width: 100, alignment: .leading)
                                    VStack(alignment: .leading) {
                                        Text("\(a.value["kind"]?.string ?? "") · \(a.value["subject"]?.string ?? "")").font(.callout.weight(.medium))
                                        Text(a.value["message"]?.string ?? "").font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                                    }
                                }
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                Text("Threshold-based. Netra does not infer router or interface drop reasons from these counters.").font(.caption).foregroundStyle(.secondary)
                GroupBox("Edge TCP intel (TCX observer)") {
                    if counts.isEmpty { KernelEmpty(text: "No edge-intel data reported. It is off unless the agent attached its edge-intel object.") }
                    else {
                        KVSection(title: "Counters", items: counts.map { (label: $0.id, value: CellFormat.text($0.value["value"], .int)) })
                    }
                }
            }.padding()
        }
    }
}
