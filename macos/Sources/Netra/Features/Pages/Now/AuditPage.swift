// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// Audit trail: recent events (newest first) with an activity-per-hour chart and top actors/actions.
struct AuditPage: View {
    static let config = PageConfig(
        title: "Audit", endpoint: "api/v1/audit", query: [URLQueryItem(name: "limit", value: "500")],
        rowsPath: "items", idKeys: ["at", "action"],
        columns: [
            .init(title: "When", path: "at", kind: .time, width: 90),
            .init(title: "Actor", path: "actor", width: 120),
            .init(title: "Action", path: "action", width: 160),
            .init(title: "Target", path: "target", width: 200),
        ],
        stats: [
            .init(title: "Events loaded", symbol: "list.bullet.clipboard") { String($0.at("items")?.arrayCount ?? 0) },
            .init(title: "Distinct actors", symbol: "person.2") { v in
                if case .array(let a)? = v.at("items") { String(Set(a.compactMap { $0["actor"]?.string }).count) } else { "" } },
            .init(title: "Latest", symbol: "clock") { v in
                if case .array(let a)? = v.at("items") { a.compactMap { CellFormat.date($0["at"]) }.max().map { CellFormat.relative($0) } ?? "" } else { "" } },
        ],
        emptyText: "No audit events recorded yet.")

    var body: some View { DataPageView(Self.config) { _ in AuditSummaryHeader() } }
}

private struct AuditSummaryHeader: View {
    @Environment(AppModel.self) private var model
    @State private var summary: JSONValue?

    var body: some View {
        Group {
            if let summary {
                let hours = NowData.auditHours(summary)
                HStack(alignment: .top, spacing: 12) {
                    GroupBox("Events per hour") {
                        if hours.isEmpty { Text("No activity buckets").foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 70) }
                        else {
                            Chart(hours, id: \.0) { BarMark(x: .value("Hour", $0.0, unit: .hour), y: .value("Events", $0.1)) }
                                .frame(height: 90)
                        }
                    }
                    NowBars(title: "Top actors", items: NowData.auditTop(summary, key: "byActor", limit: 4))
                    NowBars(title: "Top actions", items: NowData.auditTop(summary, key: "byAction", limit: 4), tint: .indigo)
                }.padding(.horizontal).padding(.bottom, 8)
            }
        }
        .task {
            guard let c = model.client else { return }
            var req = c.request("GET", "api/v1/audit/summary", query: [URLQueryItem(name: "limit", value: "1000")]); req.timeoutInterval = 20
            summary = try? JSONDecoder().decode(JSONValue.self, from: await c.send(req))
        }
    }
}
