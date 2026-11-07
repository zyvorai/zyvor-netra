// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Operator scorecard: one 0-100 score with a band, the headline, per-factor counters and notes.
struct ScorecardPage: View {
    var body: some View {
        NowFetch(title: "Scorecard", endpoint: "api/v1/scorecard") { json in
            let score = json.at("score")?.asDouble ?? 0
            let band = NowSeverity(json.at("band")?.string)
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 20) {
                    Gauge(value: min(max(score, 0), 100), in: 0...100) { Text("Score") } currentValueLabel: { Text("\(Int(score))").font(.title.bold()) }
                        .gaugeStyle(.accessoryCircularCapacity).tint(band.tint).scaleEffect(2).frame(width: 110, height: 110)
                    VStack(alignment: .leading, spacing: 6) {
                        NowBadge(severity: band, text: (json.at("band")?.string ?? "unknown").capitalized + " band")
                        Text(json.at("headline")?.string ?? "No headline").font(.title3)
                        if let t = CellFormat.date(json.at("generatedAt")) { Text("Generated \(CellFormat.relative(t))").font(.caption).foregroundStyle(.secondary) }
                    }
                }
                .accessibilityElement(children: .combine)
                HStack(spacing: 10) {
                    ForEach(NowData.scorecardCounters(json)) { c in
                        let bad = c.name != "Health score" && c.value > 0
                        StatCard(title: c.name, value: String(Int(c.value)), symbol: bad ? "exclamationmark.triangle.fill" : "checkmark.circle", tint: bad ? .orange : .green)
                    }
                }
                GroupBox("What affects the score") {
                    let notes = json.at("notes").map { v -> [String] in if case .array(let a) = v { a.compactMap(\.string) } else { [] } } ?? []
                    if notes.isEmpty { Text("No deductions: nothing is pulling the score down.").foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading) }
                    else { VStack(alignment: .leading, spacing: 6) { ForEach(Array(notes.enumerated()), id: \.offset) { _, n in Label(n, systemImage: "minus.circle").frame(maxWidth: .infinity, alignment: .leading) } } }
                }
            }
        }
    }
}
