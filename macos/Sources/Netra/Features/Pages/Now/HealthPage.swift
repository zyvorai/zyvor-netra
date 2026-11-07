// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// Network health: score, headline TCP/DNS counters, anomalies table, top retransmitters and DNS failures.
struct HealthPage: View {
    static let config = PageConfig(
        title: "Health", endpoint: "api/v1/ebpf/health", query: [URLQueryItem(name: "limit", value: "50")],
        rowsPath: "summary.anomalies", idKeys: ["kind", "subject"],
        columns: [
            .init(title: "Severity", path: "severity", width: 80),
            .init(title: "Kind", path: "kind", width: 120),
            .init(title: "Subject", path: "subject", width: 200),
            .init(title: "Message", path: "message", width: 260),
            .init(title: "Value", path: "value", kind: .number(1), width: 70),
        ],
        stats: [
            .init(title: "Health score", symbol: "heart.text.square") { $0.at("summary.healthScore").map { "\(CellFormat.text($0, .int))/100" } ?? "" },
            .init(title: "Anomalies", symbol: "exclamationmark.triangle") { CellFormat.text($0.at("summary.anomalies").map { .number(Double($0.arrayCount)) }, .int) },
            .init(title: "TCP retrans", symbol: "arrow.triangle.2.circlepath") { CellFormat.text($0.at("summary.tcpRetransmissions"), .int) },
            .init(title: "TCP resets", symbol: "xmark.circle") { CellFormat.text($0.at("summary.tcpResets"), .int) },
            .init(title: "Avg RTT", symbol: "timer") { $0.at("summary.averageSrttUs")?.asDouble.map { CellFormat.text(.number($0 / 1000), .millis) } ?? "" },
            .init(title: "DNS failures", symbol: "network.slash") { CellFormat.text($0.at("summary.dnsFailures"), .int) },
            .init(title: "Connect failures", symbol: "bolt.slash") { CellFormat.text($0.at("summary.estimatedConnectFailures"), .int) },
        ],
        emptyText: "No anomalies detected. The network looks healthy.")

    var body: some View {
        DataPageView(Self.config) { json in
            let score = json.at("summary.healthScore")?.asDouble ?? 0
            let sev = NowData.scoreSeverity(score)
            HStack(alignment: .top, spacing: 12) {
                GroupBox("Overall") {
                    VStack(spacing: 6) {
                        Gauge(value: min(max(score, 0), 100), in: 0...100) { Text("Score") } currentValueLabel: { Text("\(Int(score))") }
                            .gaugeStyle(.accessoryCircular).tint(sev.tint).scaleEffect(1.4).frame(width: 80, height: 80)
                        NowBadge(severity: NowData.worstAnomaly(json), text: NowData.anomalyCounts(json).map { "\($0.1) \($0.0.label)" }.joined(separator: ", ").nonEmpty ?? "No anomalies")
                    }.frame(minWidth: 150)
                }
                NowBars(title: "Top TCP retransmissions", items: NowData.topRetransmitters(json, limit: 5), tint: .orange)
                NowBars(title: "Top DNS failures", items: NowData.topDNSFailures(json, limit: 5), tint: .purple)
            }.padding(.horizontal).padding(.bottom, 8)
        }
    }
}

private extension String { var nonEmpty: String? { isEmpty ? nil : self } }
extension JSONValue { var arrayCount: Int { if case .array(let a) = self { a.count } else { 0 } } }
