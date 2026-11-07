// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// GET /api/v1/ebpf/sysctl-audit: network sysctls checked against a baseline, plus cross-node outliers.
struct SysctlPage: View {
    private enum Tab: String, CaseIterable { case findings = "Findings", outliers = "Cluster outliers" }
    @State private var tab = Tab.findings
    @State private var query = ""
    @State private var minSeverity = KernelData.Severity.ok
    @State private var selection: String?
    @State private var sort = [KeyPathComparator(\KernelData.SysctlRow.name)]

    var body: some View {
        KernelLoader(title: "Sysctl audit", endpoint: "api/v1/ebpf/sysctl-audit", query: [.init(name: "limit", value: "500")]) { v, _ in
            let all = KernelData.sysctlRows(v)
            let outliers = KernelData.sysctlOutliers(v)
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        StatCard(title: "Nodes", value: v.at("summary.nodes")?.summary ?? "", symbol: "server.rack")
                        StatCard(title: "Critical", value: v.at("summary.critical")?.summary ?? "", symbol: "xmark.octagon.fill", tint: .red)
                        StatCard(title: "Warnings", value: v.at("summary.warnings")?.summary ?? "", symbol: "exclamationmark.triangle.fill", tint: .orange)
                        StatCard(title: "Informational", value: v.at("summary.informational")?.summary ?? "", symbol: "info.circle.fill", tint: .blue)
                        StatCard(title: "Node outliers", value: v.at("summary.outliers")?.summary ?? "", symbol: "person.crop.circle.badge.exclamationmark")
                    }.padding([.horizontal, .top])
                }.padding(.bottom, 8)
                HStack {
                    Picker("View", selection: $tab) { ForEach(Tab.allCases, id: \.self) { Text($0.rawValue) } }.pickerStyle(.segmented).fixedSize()
                    if tab == .findings {
                        Picker("Show", selection: $minSeverity) {
                            Text("All").tag(KernelData.Severity.ok); Text("Warning and worse").tag(KernelData.Severity.warning)
                            Text("Critical only").tag(KernelData.Severity.critical)
                        }.pickerStyle(.menu).fixedSize()
                    }
                    Spacer()
                }.padding(.horizontal).padding(.bottom, 6)
                if tab == .findings { findings(all) } else { outlierList(outliers) }
                if case .array(let l)? = v.at("limitations"), !l.isEmpty {
                    Text(l.map(\.summary).joined(separator: " ")).font(.caption).foregroundStyle(.secondary).padding(8).frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .searchable(text: $query, prompt: "Filter sysctls")
    }

    private func findings(_ all: [KernelData.SysctlRow]) -> some View {
        let rows = all.filter { ($0.severity <= minSeverity || minSeverity == .ok)
            && (query.isEmpty || [$0.name, $0.node, $0.category, $0.iface, $0.current].contains { $0.localizedCaseInsensitiveContains(query) }) }.sorted(using: sort)
        return HSplitView {
            if rows.isEmpty { KernelEmpty(text: all.isEmpty ? "No sysctl data reported." : "No matches") } else {
                Table(rows, selection: $selection, sortOrder: $sort) {
                    TableColumn("Severity", value: \.severity.rawValue) { SeverityLabel(severity: $0.severity) }.width(min: 90)
                    TableColumn("Sysctl", value: \.name) { r in Text(r.name + (r.iface.isEmpty ? "" : " [\(r.iface)]")).textSelection(.enabled) }.width(min: 180)
                    TableColumn("Node", value: \.node) { Text($0.node) }.width(min: 80)
                    TableColumn("Current", value: \.current) { Text($0.current).monospacedDigit() }.width(min: 60)
                    TableColumn("Expected", value: \.expected) { r in
                        Text(r.expected.isEmpty ? "–" : r.expected).monospacedDigit().foregroundStyle(r.deviates ? Color.orange : .secondary)
                    }.width(min: 60)
                    TableColumn("Category", value: \.category) { Text($0.category) }.width(min: 70)
                }
            }
            Group {
                if let r = rows.first(where: { $0.id == selection }) {
                    List {
                        Section(r.name) {
                            LabeledContent("Node", value: r.node)
                            LabeledContent("Interface", value: r.iface.isEmpty ? "–" : r.iface)
                            LabeledContent("Current", value: r.current)
                            LabeledContent("Expected", value: r.expected.isEmpty ? "no single correct value" : r.expected)
                            SeverityLabel(severity: r.severity)
                        }
                        Section("Why it matters") { Text(r.rationale).textSelection(.enabled) }
                    }
                } else { ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select a sysctl for its rationale.")) }
            }.frame(minWidth: 240, idealWidth: 300)
        }
    }

    private func outlierList(_ o: [KernelData.SysctlOutlier]) -> some View {
        let rows = o.filter { query.isEmpty || $0.name.localizedCaseInsensitiveContains(query) || $0.nodes.contains { $0.localizedCaseInsensitiveContains(query) } }
        return Group {
            if rows.isEmpty { KernelEmpty(text: "No node disagrees with the cluster majority.", symbol: "checkmark.circle") } else {
                Table(rows) {
                    TableColumn("Sysctl") { r in Text(r.name + (r.iface.isEmpty ? "" : " [\(r.iface)]")).textSelection(.enabled) }.width(min: 200)
                    TableColumn("Category") { Text($0.category) }.width(min: 70)
                    TableColumn("Majority value") { Text($0.majority).monospacedDigit() }.width(min: 90)
                    TableColumn("Outlier nodes") { Text($0.nodes.joined(separator: ", ")) }.width(min: 160)
                }
            }
        }
    }
}
