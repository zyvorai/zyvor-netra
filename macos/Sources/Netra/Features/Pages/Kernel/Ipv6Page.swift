// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// GET /api/v1/ebpf/ipv6: IPv6 extension-header and fragmentation counters per node, direction and hook.
struct Ipv6Page: View {
    @State private var query = ""
    @State private var selection: String?
    @State private var sort = [KeyPathComparator(\Ipv6Data.ExtRow.fragmented, order: .reverse)]

    var body: some View {
        KernelLoader(title: "IPv6", endpoint: "api/v1/ebpf/ipv6", query: [.init(name: "limit", value: "200")], liveEvery: 10) { v, _ in
            let all = Ipv6Data.extRows(v)
            let anomalies = Ipv6Data.anomalies(v)
            let rows = all.filter { query.isEmpty || [$0.node, $0.direction, $0.hook].contains { $0.localizedCaseInsensitiveContains(query) } }.sorted(using: sort)
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        StatCard(title: "IPv6 packets", value: v.at("summary.packets")?.summary ?? "0", symbol: "network")
                        StatCard(title: "With extension headers", value: v.at("summary.extHeaderPackets")?.summary ?? "0", symbol: "rectangle.stack")
                        StatCard(title: "Fragmented", value: v.at("summary.fragmented")?.summary ?? "0", symbol: "scissors", tint: .orange)
                        StatCard(title: "Non-first fragments", value: v.at("summary.nonFirstFragments")?.summary ?? "0", symbol: "scissors")
                        StatCard(title: "Chain truncated", value: v.at("summary.chainTruncated")?.summary ?? "0", symbol: "exclamationmark.triangle.fill", tint: .orange)
                    }.padding([.horizontal, .top])
                }.padding(.bottom, 8)
                if !anomalies.isEmpty {
                    GroupBox("Anomalies") {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(anomalies) { a in
                                HStack(alignment: .firstTextBaseline) {
                                    SeverityLabel(severity: a.severity).frame(width: 100, alignment: .leading)
                                    Text(a.subject).bold()
                                    Text(a.message).foregroundStyle(.secondary).textSelection(.enabled)
                                }.font(.callout)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }.padding(.horizontal).padding(.bottom, 8)
                }
                HSplitView {
                    if rows.isEmpty { KernelEmpty(text: all.isEmpty ? "No IPv6 extension-header counters reported." : "No matches") } else {
                        Table(rows, selection: $selection, sortOrder: $sort) {
                            TableColumn("Node", value: \.node) { Text($0.node) }.width(min: 80)
                            TableColumn("Direction", value: \.direction) { Text($0.direction) }.width(min: 60)
                            TableColumn("Hook", value: \.hook) { Text($0.hook) }.width(min: 60)
                            TableColumn("Packets", value: \.packets) { Text(Int($0.packets).formatted()).monospacedDigit() }.width(min: 70)
                            TableColumn("Ext hdr", value: \.extHeaderPackets) { Text(Int($0.extHeaderPackets).formatted()).monospacedDigit() }.width(min: 60)
                            TableColumn("Fragmented", value: \.fragmented) { Text(Int($0.fragmented).formatted()).monospacedDigit() }.width(min: 70)
                            TableColumn("Frag %") { r in Text(r.fragmentRate.map { String(format: "%.1f%%", $0 * 100) } ?? "–").monospacedDigit() }.width(min: 55)
                            TableColumn("Truncated", value: \.chainTruncated) { Text(Int($0.chainTruncated).formatted()).monospacedDigit() }.width(min: 65)
                        }
                    }
                    Group {
                        if let r = rows.first(where: { $0.id == selection }) {
                            List {
                                Section("\(r.node), \(r.direction) \(r.hook)") {
                                    LabeledContent("Packets", value: Int(r.packets).formatted())
                                    LabeledContent("With extension headers", value: Int(r.extHeaderPackets).formatted())
                                    LabeledContent("Total extension headers", value: Int(r.totalExtHeaders).formatted())
                                    LabeledContent("Fragmented", value: Int(r.fragmented).formatted())
                                    LabeledContent("Non-first fragments", value: Int(r.nonFirstFragments).formatted())
                                    LabeledContent("More-fragments set", value: Int(r.moreFragments).formatted())
                                    LabeledContent("Chain truncated", value: Int(r.chainTruncated).formatted())
                                }
                                Section("Note") { Text("Counters are node-level and cumulative since the agent started. Truncated chains exceeded the bounded walk, so L4 and L7 parsing was skipped for those packets.").font(.caption) }
                            }
                        } else { ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select a row for the full counters.")) }
                    }.frame(minWidth: 240, idealWidth: 300)
                }
            }
        }
        .searchable(text: $query, prompt: "Filter nodes, hooks")
    }
}
