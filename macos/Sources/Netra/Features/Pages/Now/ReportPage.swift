// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import AppKit
import NetraKit

/// Operator report: headline, key counters, attention list and recent audit. Copy as Markdown is a read-only GET.
struct ReportPage: View {
    @Environment(AppModel.self) private var model
    @State private var copied: String?

    var body: some View {
        NowFetch(title: "Report", endpoint: "api/v1/report", query: [URLQueryItem(name: "format", value: "json")], liveEvery: nil) { json in
            VStack(alignment: .leading, spacing: 14) {
                Text(json.at("headline")?.string ?? "Operator report").font(.title2.weight(.semibold))
                HStack(spacing: 10) {
                    StatCard(title: "Mode", value: json.at("mode")?.string ?? "", symbol: "switch.2")
                    StatCard(title: "Health", value: json.at("healthScore").map { "\(CellFormat.text($0, .int))/100" } ?? "", symbol: "heart.text.square",
                             tint: NowData.scoreSeverity(json.at("healthScore")?.asDouble ?? 0).tint)
                    StatCard(title: "Agents", value: "\(CellFormat.text(json.at("agents"), .int)) (\(CellFormat.text(json.at("staleAgents"), .int)) stale)", symbol: "server.rack")
                    StatCard(title: "Packets", value: CellFormat.text(json.at("packets"), .int), symbol: "shippingbox")
                    StatCard(title: "Blocked", value: CellFormat.text(json.at("blocked"), .int), symbol: "hand.raised")
                }
                HStack(spacing: 10) {
                    StatCard(title: "Anomalies", value: CellFormat.text(json.at("anomalyCount"), .int), symbol: "exclamationmark.triangle")
                    StatCard(title: "Drift", value: CellFormat.text(json.at("driftFindings"), .int), symbol: "arrow.left.arrow.right")
                    StatCard(title: "Rate drift", value: CellFormat.text(json.at("rateDriftFindings"), .int), symbol: "waveform.path.ecg")
                    StatCard(title: "High exposure", value: CellFormat.text(json.at("highExposure"), .int), symbol: "lock.open")
                    StatCard(title: "Incidents", value: CellFormat.text(json.at("incidentClusters"), .int), symbol: "bolt.horizontal")
                    StatCard(title: "TCP retrans", value: CellFormat.text(json.at("tcpRetransmissions"), .int), symbol: "arrow.triangle.2.circlepath")
                    StatCard(title: "DNS failures", value: CellFormat.text(json.at("dnsFailures"), .int), symbol: "network.slash")
                }
                if let lease = NowData.realDate(json.at("leaseExpiresAt")) {
                    Label("Enforce lease \(lease > Date() ? "expires" : "expired") \(CellFormat.relative(lease))", systemImage: "timer")
                }
                list("Needs attention", symbol: "exclamationmark.circle", json.at("attention"), empty: "Nothing needs attention.")
                list("Recent audit", symbol: "list.bullet.clipboard", json.at("recentAudit"), empty: "No recent audit events.")
                HStack {
                    Button("Copy as Markdown", systemImage: "doc.on.doc") { Task { await copy() } }
                    if let copied { Text(copied).font(.caption).foregroundStyle(.secondary) }
                }
            }
        }
    }

    private func list(_ title: String, symbol: String, _ v: JSONValue?, empty: String) -> some View {
        let items: [String] = { if case .array(let a)? = v { a.compactMap(\.string) } else { [] } }()
        return GroupBox(title) {
            VStack(alignment: .leading, spacing: 5) {
                if items.isEmpty { Text(empty).foregroundStyle(.secondary) }
                ForEach(Array(items.enumerated()), id: \.offset) { _, t in Label(t, systemImage: symbol).textSelection(.enabled) }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func copy() async {
        guard let c = model.client else { return }
        do {
            let data = try await c.send(c.request("GET", "api/v1/report", query: [URLQueryItem(name: "format", value: "markdown")]))
            NSPasteboard.general.clearContents(); NSPasteboard.general.setString(String(decoding: data, as: UTF8.self), forType: .string)
            copied = "Copied"
        } catch { copied = "Copy failed: \(error.localizedDescription)" }
    }
}
