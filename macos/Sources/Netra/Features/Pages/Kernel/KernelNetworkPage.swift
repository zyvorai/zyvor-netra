// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Shared K6 window choices for the kernel-network page (the controller parses these as Go durations).
enum K6Window: String, CaseIterable, Identifiable {
    case m1 = "1m", m5 = "5m", m15 = "15m", h1 = "1h"
    var id: String { rawValue }
}

/// GET /api/v1/ebpf/kernel-network: findings correlating drops with softnet, NIC, qdisc and sysctl state.
/// Apply and rollback commands are shown as text to copy; this page never changes a kernel tunable.
struct KernelNetworkPage: View {
    private enum Tab: String, CaseIterable { case findings = "Findings", windows = "Node windows" }
    @State private var tab = Tab.findings
    @State private var window = K6Window.m5
    @State private var query = ""
    @State private var minSeverity = KernelData.Severity.ok
    @State private var selection: String?

    var body: some View {
        KernelLoader(title: "Kernel network", endpoint: "api/v1/ebpf/kernel-network", query: [.init(name: "window", value: window.rawValue)], liveEvery: 15) { v, _ in
            let all = Ipv6Data.findings(v)
            let shown = all.filter { ($0.severity <= minSeverity || minSeverity == .ok)
                && (query.isEmpty || [$0.node, $0.layer, $0.signal, $0.tunable].contains { $0.localizedCaseInsensitiveContains(query) }) }
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        StatCard(title: "Nodes", value: v.at("summary.nodes")?.summary ?? "0", symbol: "server.rack")
                        StatCard(title: "Findings", value: v.at("summary.findings")?.summary ?? "0", symbol: "list.bullet")
                        StatCard(title: "Critical", value: v.at("summary.critical")?.summary ?? "0", symbol: "xmark.octagon.fill", tint: .red)
                        StatCard(title: "Warnings", value: v.at("summary.warnings")?.summary ?? "0", symbol: "exclamationmark.triangle.fill", tint: .orange)
                        StatCard(title: "Warming up", value: v.at("summary.warming")?.summary ?? "0", symbol: "hourglass")
                    }.padding([.horizontal, .top])
                }.padding(.bottom, 8)
                HStack {
                    Picker("View", selection: $tab) { ForEach(Tab.allCases, id: \.self) { Text($0.rawValue) } }.pickerStyle(.segmented).fixedSize()
                    Picker("Window", selection: $window) { ForEach(K6Window.allCases) { Text($0.rawValue).tag($0) } }.pickerStyle(.menu).fixedSize()
                    if tab == .findings {
                        Picker("Show", selection: $minSeverity) {
                            Text("All").tag(KernelData.Severity.ok); Text("Warning and worse").tag(KernelData.Severity.warning)
                            Text("Critical only").tag(KernelData.Severity.critical)
                        }.pickerStyle(.menu).fixedSize()
                    }
                    Spacer()
                }.padding(.horizontal).padding(.bottom, 6)
                if tab == .findings { findings(shown, total: all.count) } else { windows(v) }
                if case .array(let l)? = v.at("limitations"), !l.isEmpty {
                    Text(l.map(\.summary).joined(separator: " ")).font(.caption).foregroundStyle(.secondary).padding(8).frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .searchable(text: $query, prompt: "Filter findings")
    }

    private func findings(_ rows: [Ipv6Data.Finding], total: Int) -> some View {
        HSplitView {
            if rows.isEmpty { KernelEmpty(text: total == 0 ? "No kernel network findings." : "No matches", symbol: "checkmark.circle") } else {
                Table(rows, selection: $selection) {
                    TableColumn("Severity") { SeverityLabel(severity: $0.severity) }.width(min: 90)
                    TableColumn("Node") { Text($0.node) }.width(min: 80)
                    TableColumn("Layer") { Text($0.layer) }.width(min: 90)
                    TableColumn("Signal") { Text($0.signal).lineLimit(1) }.width(min: 160)
                    TableColumn("Tunable") { Text($0.tunable.isEmpty ? "–" : $0.tunable).textSelection(.enabled) }.width(min: 140)
                }
            }
            Group {
                if let f = rows.first(where: { $0.id == selection }) { K6FindingDetail(finding: f) }
                else { ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select a finding for evidence and guidance.")) }
            }.frame(minWidth: 280, idealWidth: 340)
        }
    }

    private func windows(_ v: JSONValue) -> some View {
        let rows = Ipv6Data.windows(v)
        return Group {
            if rows.isEmpty { KernelEmpty(text: "No nodes reporting.") } else {
                List(rows) { w in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(w.node).bold()
                            if w.warming { Label("Warming up, no interval yet", systemImage: "hourglass").foregroundStyle(.secondary) }
                            if w.reset { Label("Counter reset detected", systemImage: "arrow.counterclockwise").foregroundStyle(.orange) }
                            if let s = w.seconds { Text(String(format: "interval %.0fs", s)).foregroundStyle(.secondary) }
                            Spacer()
                            Text("\(w.counters) counters").font(.caption).foregroundStyle(.secondary)
                        }
                        if !w.rates.isEmpty {
                            HStack(spacing: 16) {
                                ForEach(w.rates, id: \.label) { r in
                                    VStack(alignment: .leading) {
                                        Text(r.label).font(.caption).foregroundStyle(.secondary)
                                        Text(String(format: "%.2f/s", r.perSecond)).monospacedDigit().foregroundStyle(r.perSecond > 0 ? Color.orange : .primary)
                                    }
                                }
                            }
                        }
                    }.padding(.vertical, 2)
                }
            }
        }
    }
}

/// Detail pane for one finding. Commands are selectable text only; nothing here runs them.
struct K6FindingDetail: View {
    let finding: Ipv6Data.Finding
    var body: some View {
        List {
            Section("\(finding.layer): \(finding.signal)") {
                SeverityLabel(severity: finding.severity)
                LabeledContent("Node", value: finding.node)
                if let w = finding.windowSeconds { LabeledContent("Window", value: String(format: "%.0fs", w)) }
            }
            if !finding.evidence.isEmpty {
                Section("Evidence") { ForEach(finding.evidence, id: \.self) { Text($0).font(.system(.caption, design: .monospaced)).textSelection(.enabled) } }
            }
            Section("Explanation") { Text(finding.explanation).textSelection(.enabled) }
            Section("Recommendation") { Text(finding.recommendation).textSelection(.enabled) }
            if !finding.tunable.isEmpty {
                Section("Tunable (guidance only, Netra never applies it)") {
                    LabeledContent("Name", value: finding.tunable)
                    LabeledContent("Current", value: finding.currentValue.isEmpty ? "unknown" : finding.currentValue)
                    LabeledContent("Suggested", value: finding.suggestedValue.isEmpty ? "none" : finding.suggestedValue)
                    if !finding.applyCommand.isEmpty { K6Command(label: "Apply on the node", text: finding.applyCommand) }
                    if !finding.rollbackCommand.isEmpty { K6Command(label: "Roll back", text: finding.rollbackCommand) }
                }
            }
            Section("Risk") { Text(finding.risk).textSelection(.enabled) }
        }
    }
}

struct K6Command: View {
    let label: String
    let text: String
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(text).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
        }
    }
}
