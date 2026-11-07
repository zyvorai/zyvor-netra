// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// SLO status: compliance and error budget per objective, with multi-window burn rates.
struct SLOPage: View {
    var body: some View {
        NowFetch(title: "SLO", endpoint: "api/v1/slo") { json in SLOBody(json: json) }
    }
}

private struct SLOBody: View {
    let json: JSONValue
    @State private var selection: SLOItem.ID?
    @State private var sort = [KeyPathComparator(\SLOItem.severityRank, order: .reverse)]

    var body: some View {
        let items = NowData.sloItems(json).sorted(using: sort)
        let enabled = json["enabled"] != .bool(false)
        VStack(alignment: .leading, spacing: 12) {
            if items.isEmpty {
                ContentUnavailableView(enabled ? "No SLOs defined" : "SLOs are not enabled", systemImage: "target",
                    description: Text(enabled ? "Define SLOs in the controller configuration to see budgets here." : "The controller has no SLO definitions configured."))
                    .frame(minHeight: 300)
            } else {
                let firing = items.filter { $0.severity > .ok || $0.firing }.count
                let worst = items.filter(\.hasData).map(\.budgetRemaining).min()
                HStack(spacing: 10) {
                    StatCard(title: "Objectives", value: "\(items.count)", symbol: "target")
                    StatCard(title: "Burning", value: "\(firing)", symbol: firing > 0 ? "flame.fill" : "checkmark.circle.fill", tint: firing > 0 ? .red : .green)
                    StatCard(title: "No data", value: "\(items.filter { !$0.hasData }.count)", symbol: "questionmark.circle", tint: .secondary)
                    StatCard(title: "Lowest budget", value: worst.map { String(format: "%.0f%%", $0 * 100) } ?? "", symbol: "gauge.with.dots.needle.33percent")
                }
                GroupBox("Error budget remaining") {
                    Chart(items.filter(\.hasData)) { i in
                        BarMark(x: .value("Budget", i.budgetRemaining * 100), y: .value("SLO", i.name))
                            .foregroundStyle(i.severity.tint)
                            .annotation(position: .trailing) { Text(String(format: "%.0f%%", i.budgetRemaining * 100)).font(.caption2) }
                    }
                    .chartXScale(domain: 0...110).chartXAxisLabel("% of budget left")
                    .frame(height: CGFloat(max(items.count, 2)) * 26 + 40)
                }
                HSplitView {
                    Table(items, selection: $selection, sortOrder: $sort) {
                        TableColumn("Status", value: \.severityRank) { i in NowBadge(severity: i.severity, text: i.severity == .ok ? "OK" : i.severity.rawLabel) }.width(min: 90)
                        TableColumn("Name", value: \.name).width(min: 120)
                        TableColumn("SLI", value: \.sli).width(min: 80)
                        TableColumn("Scope", value: \.scope).width(min: 80)
                        TableColumn("Window", value: \.window).width(min: 50)
                        TableColumn("Target", value: \.targetPct) { Text(String(format: "%.2f%%", $0.targetPct)).monospacedDigit() }.width(min: 60)
                        TableColumn("Compliance", value: \.compliancePct) { i in Text(i.hasData ? String(format: "%.3f%%", i.compliancePct) : "no data").monospacedDigit() }.width(min: 80)
                        TableColumn("Budget", value: \.budgetRemaining) { i in Text(i.hasData ? String(format: "%.0f%%", i.budgetRemaining * 100) : "–").monospacedDigit() }.width(min: 60)
                        TableColumn("Errors / total", value: \.errors) { i in Text("\(Int(i.errors)) / \(Int(i.total))").monospacedDigit() }.width(min: 90)
                    }.frame(minHeight: 260)
                    SLODetail(item: items.first { $0.id == selection }).frame(minWidth: 260, idealWidth: 320)
                }.frame(minHeight: 280)
            }
        }
    }
}

private struct SLODetail: View {
    let item: SLOItem?
    var body: some View {
        if let item {
            VStack(alignment: .leading, spacing: 10) {
                Text(item.name).font(.headline)
                NowBadge(severity: item.severity)
                Text("Burn-rate windows: firing when both long and short burn exceed the threshold.").font(.caption).foregroundStyle(.secondary)
                ForEach(item.windows) { w in
                    GroupBox {
                        VStack(alignment: .leading, spacing: 3) {
                            HStack { Text(w.kind.capitalized).bold(); Spacer()
                                NowBadge(severity: w.firing ? .critical : .ok, text: w.firing ? "Firing" : "Quiet") }
                            Text("Long (\(w.long)): \(String(format: "%.2f", w.longBurn))x   Short (\(w.short)): \(String(format: "%.2f", w.shortBurn))x")
                            Text("Threshold \(String(format: "%.1f", w.threshold))x").foregroundStyle(.secondary)
                        }.font(.caption).monospacedDigit().frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                Spacer()
            }.padding()
        } else {
            ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select an SLO to see its burn rates."))
        }
    }
}

extension SLOItem {
    var severityRank: Int { severity.rank }
}
extension NowSeverity {
    /// SLO burn severities are page/ticket; show the operator word.
    var rawLabel: String { self == .high ? "Page" : self == .warning ? "Ticket" : label }
}
