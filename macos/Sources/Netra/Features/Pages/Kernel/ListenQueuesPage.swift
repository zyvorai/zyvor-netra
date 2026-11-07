// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// GET /api/v1/listen-queues: listeners whose TCP accept queue is, or has been, under pressure.
struct ListenQueuesPage: View {
    private let config = PageConfig(
        title: "Listen queues", endpoint: "api/v1/listen-queues", query: [.init(name: "top", value: "100")],
        rowsPath: "top", idKeys: ["node", "addr", "port"],
        columns: [
            PageColumn(title: "Node", path: "node"), PageColumn(title: "Address", path: "addr"),
            PageColumn(title: "Port", path: "port", kind: .int, width: 50),
            PageColumn(title: "Queue", path: "queue", kind: .int, width: 50), PageColumn(title: "Max", path: "max", kind: .int, width: 50),
            PageColumn(title: "SYN_RECV", path: "synRecv", kind: .int, width: 60),
            PageColumn(title: "Peak", path: "peak", kind: .int, width: 50), PageColumn(title: "Peak %", path: "peakPct", kind: .percent, width: 60),
            PageColumn(title: "Family", path: "family", width: 50),
        ],
        stats: [
            PageStat(title: "Nodes sampling", symbol: "server.rack") { $0.at("nodesReporting")?.summary ?? "" },
            PageStat(title: "Not sampling", symbol: "eye.slash", tint: .orange) { $0.at("nodesNotReporting")?.summary ?? "" },
            PageStat(title: "Listeners", symbol: "ear") { $0.at("listeners")?.summary ?? "" },
            PageStat(title: "Full (refusing)", symbol: "xmark.octagon.fill", tint: .red) { $0.at("full")?.summary ?? "" },
            PageStat(title: "Saturated ≥80%", symbol: "exclamationmark.triangle.fill", tint: .orange) { $0.at("saturated")?.summary ?? "" },
            PageStat(title: "Half-open (SYN_RECV)", symbol: "hourglass") { $0.at("synRecv")?.summary ?? "" },
        ],
        emptyText: "No listener is under accept-queue pressure.")

    var body: some View {
        DataPageView(config) { v in
            let buckets = KernelData.listenBuckets(v)
            let silent = v.at("nodes").map { JSONValue.rows(of: $0) }?.filter { $0.at("reporting") != .bool(true) } ?? []
            VStack(alignment: .leading, spacing: 8) {
                if !buckets.isEmpty {
                    GroupBox("Accept-queue fill, samples since agent start (idle listeners dominate Empty)") {
                        Chart(buckets) { b in
                            BarMark(x: .value("Fill", b.label), y: .value("Samples", b.count))
                                .foregroundStyle(b.id == "full" ? Color.red : b.id == "lt_100" ? .orange : .accentColor)
                                .annotation(position: .top) { Text(Int(b.count).formatted()).font(.caption2).monospacedDigit() }
                        }
                        .chartXScale(domain: buckets.map(\.label))
                        .frame(height: 110)
                        .accessibilityLabel("Fill histogram")
                        .accessibilityValue(buckets.map { "\($0.label): \(Int($0.count))" }.joined(separator: ", "))
                    }
                }
                if !silent.isEmpty {
                    Label("Silent nodes, not evidence of empty queues: " + silent.map { ($0.at("node")?.string ?? "?") + ($0.at("unavailable")?.string.map { " (\($0))" } ?? "") }.joined(separator: "; "),
                          systemImage: "eye.slash").font(.caption).foregroundStyle(.orange)
                }
            }.padding(.horizontal).padding(.bottom, 8)
        }
    }
}

private extension JSONValue {
    static func rows(of v: JSONValue) -> [JSONValue] { if case .array(let a) = v { a } else { [] } }
}
