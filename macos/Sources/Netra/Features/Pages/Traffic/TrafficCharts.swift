// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// Horizontal ranked bars; the blocked share is stacked and named in the legend (not color alone).
struct RankedBarsCard: View {
    let title: String
    let bars: [RankedBar]
    var unit = "packets"

    var body: some View {
        if !bars.isEmpty {
            GroupBox(title) {
                Chart {
                    ForEach(bars) { b in
                        BarMark(x: .value("Allowed", b.allowed), y: .value("Name", b.label))
                            .foregroundStyle(by: .value("Verdict", "Allowed"))
                            .accessibilityLabel(b.label)
                            .accessibilityValue("\(TrafficData.compact(b.value)) \(unit), \(TrafficData.compact(b.blocked)) blocked")
                        if b.blocked > 0 {
                            BarMark(x: .value("Blocked", b.blocked), y: .value("Name", b.label))
                                .foregroundStyle(by: .value("Verdict", "Blocked"))
                                .annotation(position: .trailing) {
                                    Text("\(TrafficData.compact(b.blocked)) blocked").font(.caption2).foregroundStyle(.secondary)
                                }
                        }
                    }
                }
                .chartForegroundStyleScale(["Allowed": Color.accentColor, "Blocked": Color.red])
                .chartYScale(domain: bars.map(\.label))
                .chartXAxis { AxisMarks { v in AxisGridLine(); AxisValueLabel { if let d = v.as(Double.self) { Text(TrafficData.compact(d)) } } } }
                .frame(height: max(110, CGFloat(bars.count) * 22 + 40))
            }
            .padding(.horizontal).padding(.bottom, 8)
        }
    }
}

/// Share-of-total donut with a legend that also prints the percentage.
struct ShareDonutCard: View {
    let title: String
    let bars: [RankedBar]

    var body: some View {
        if !bars.isEmpty {
            let total = bars.reduce(0) { $0 + $1.value }
            GroupBox(title) {
                HStack(alignment: .center, spacing: 24) {
                    Chart(bars) { b in
                        SectorMark(angle: .value("Packets", b.value), innerRadius: .ratio(0.6), angularInset: 1.5)
                            .foregroundStyle(by: .value("Protocol", b.label))
                            .accessibilityLabel(b.label)
                            .accessibilityValue(TrafficData.percent(b.value, of: total))
                    }
                    .chartLegend(.hidden)
                    .frame(width: 140, height: 140)
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(bars) { b in
                            HStack {
                                Text(b.label).font(.callout.weight(.medium))
                                Spacer(minLength: 12)
                                Text("\(TrafficData.compact(b.value)) · \(TrafficData.percent(b.value, of: total))").monospacedDigit().foregroundStyle(.secondary)
                                if b.blocked > 0 { Label("\(TrafficData.compact(b.blocked)) blocked", systemImage: "xmark.octagon").font(.caption).foregroundStyle(.red) }
                            }
                        }
                    }.frame(maxWidth: 420)
                    Spacer()
                }
            }
            .padding(.horizontal).padding(.bottom, 8)
        }
    }
}

/// Segmented tab bar shared by the multi-endpoint pages.
struct TrafficTabs<T: Hashable & CaseIterable & RawRepresentable>: View where T.RawValue == String, T.AllCases: RandomAccessCollection {
    @Binding var selection: T
    var body: some View {
        Picker("View", selection: $selection) {
            ForEach(T.allCases, id: \.self) { Text($0.rawValue).tag($0) }
        }
        .pickerStyle(.segmented).labelsHidden()
        .padding([.horizontal, .top]).padding(.bottom, 6)
    }
}
