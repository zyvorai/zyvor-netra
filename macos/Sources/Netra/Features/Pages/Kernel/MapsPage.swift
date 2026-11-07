// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// GET /api/v1/ebpf/maps: the controller's desired contents of each Netra datapath map family and how full
/// each is against its capacity. Read-only: this never writes to or pins over any map (Cilium's included).
struct MapsPage: View {
    @State private var query = ""
    @State private var selection: String?
    @State private var groupFilter = "All"

    var body: some View {
        KernelLoader(title: "BPF maps", endpoint: "api/v1/ebpf/maps") { v, _ in
            let all = KernelData.mapPressures(v)
            let groups = ["All"] + Array(Set(all.map(\.group))).sorted()
            let rows = all.filter { (groupFilter == "All" || $0.group == groupFilter)
                && (query.isEmpty || $0.title.localizedCaseInsensitiveContains(query) || $0.bpfMap.localizedCaseInsensitiveContains(query)
                    || $0.entries.contains { $0.localizedCaseInsensitiveContains(query) }) }
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        StatCard(title: "Filled maps", value: v.at("filledMaps")?.summary ?? "", symbol: "map")
                        StatCard(title: "Empty maps", value: v.at("emptyMaps")?.summary ?? "", symbol: "map.fill")
                        StatCard(title: "Total entries", value: v.at("totalEntries")?.summary ?? "", symbol: "number")
                        StatCard(title: "Near capacity (≥70%)", value: String(all.filter { $0.level <= .warning }.count),
                                 symbol: "gauge.with.dots.needle.67percent", tint: .orange)
                        StatCard(title: "Mode", value: v.at("mode")?.string ?? "", symbol: "switch.2")
                        StatCard(title: "Revision", value: v.at("revision")?.summary ?? "", symbol: "number.circle")
                    }.padding([.horizontal, .top])
                }
                HStack {
                    Picker("Group", selection: $groupFilter) { ForEach(groups, id: \.self) { Text($0.capitalized) } }.pickerStyle(.menu).fixedSize()
                    Text(v.at("note")?.string ?? "").font(.caption).foregroundStyle(.secondary).lineLimit(2)
                    Spacer()
                    Text(v.at("pinRoot")?.string ?? "").font(.caption.monospaced()).foregroundStyle(.secondary)
                }.padding(.horizontal).padding(.vertical, 6)
                HSplitView {
                    if rows.isEmpty { KernelEmpty(text: query.isEmpty ? "No map families reported." : "No matches") } else {
                        Table(rows, selection: $selection) {
                            TableColumn("Map") { (m: KernelData.MapPressure) in VStack(alignment: .leading) { Text(m.title); Text(m.bpfMap).font(.caption).foregroundStyle(.secondary) } }.width(min: 150)
                            TableColumn("Group") { Text($0.group) }.width(min: 60)
                            TableColumn("Fill") { FillBar(ratio: $0.ratio) }.width(min: 160)
                            TableColumn("Entries") { Text($0.count.formatted()).monospacedDigit() }.width(min: 60)
                            TableColumn("Capacity") { Text($0.limit > 0 ? $0.limit.formatted() : "–").monospacedDigit() }.width(min: 70)
                        }
                    }
                    detail(rows.first { $0.id == selection }).frame(minWidth: 240, idealWidth: 320)
                }
            }
        }
        .searchable(text: $query, prompt: "Filter maps and entries")
        .linkFilter(text: $query)
    }

    @ViewBuilder private func detail(_ m: KernelData.MapPressure?) -> some View {
        if let m {
            List {
                Section(m.title) {
                    LabeledContent("BPF map", value: m.bpfMap)
                    LabeledContent("Entries", value: "\(m.count) of \(m.limit > 0 ? String(m.limit) : "unknown")")
                    FillBar(ratio: m.ratio)
                }
                Section("Entries (\(m.entries.count) shown)") {
                    if m.entries.isEmpty { Text("Empty").foregroundStyle(.secondary) }
                    ForEach(Array(m.entries.enumerated()), id: \.offset) { _, e in Text(e).font(.callout.monospaced()).textSelection(.enabled) }
                }
            }
        } else { ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select a map to see its entries.")) }
    }
}
