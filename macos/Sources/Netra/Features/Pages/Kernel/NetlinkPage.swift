// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// GET /api/v1/netlink (+ /netlink/findings): read-only recording of kernel link, address, route and
/// neighbor changes. Requester attribution is comm, pid and cgroup only. Nothing here changes the network.
struct NetlinkPage: View {
    private enum Tab: String, CaseIterable { case events = "Events", findings = "Findings", nodes = "Recorder health" }
    @State private var tab = Tab.events
    @State private var since = "1h"
    @State private var kind = "all"
    @State private var query = ""
    @State private var selection: String?
    @State private var sort = [KeyPathComparator(\KernelData.NetlinkRow.timeSort, order: .reverse)]

    private var q: [URLQueryItem] {
        var r = [URLQueryItem(name: "limit", value: "1000"), URLQueryItem(name: "since", value: since)]
        if kind != "all" { r.append(.init(name: "kind", value: kind)) }
        return r
    }

    var body: some View {
        KernelLoader(title: "Netlink changes", endpoint: "api/v1/netlink", query: q,
                     secondary: [("api/v1/netlink/findings", [])], liveEvery: 5) { v, extra in
            let all = KernelData.netlinkRows(v)
            let rows = all.filter { query.isEmpty || [$0.node, $0.kind, $0.iface, $0.subject, $0.comm, $0.action].contains { $0.localizedCaseInsensitiveContains(query) } }.sorted(using: sort)
            let findings = KernelData.findings((extra.first ?? nil) ?? .null)
            let nodes = KernelData.netlinkNodes(v)
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        StatCard(title: "Changes (\(since))", value: String(all.count), symbol: "arrow.triangle.branch")
                        StatCard(title: "By a process", value: String(all.filter { $0.origin == "process" }.count), symbol: "person.fill")
                        StatCard(title: "By the kernel", value: String(all.filter { $0.origin == "kernel" }.count), symbol: "cpu")
                        StatCard(title: "Findings", value: String(findings.count), symbol: "exclamationmark.triangle.fill", tint: findings.isEmpty ? .green : .orange)
                        StatCard(title: "Lossy nodes", value: String(nodes.filter(\.lossy).count), symbol: "tray.and.arrow.down.fill", tint: nodes.contains { $0.lossy } ? .red : .green)
                    }.padding([.horizontal, .top])
                }.padding(.bottom, 8)
                HStack {
                    Picker("View", selection: $tab) { ForEach(Tab.allCases, id: \.self) { Text($0.rawValue) } }.pickerStyle(.segmented).fixedSize()
                    Picker("Window", selection: $since) { ForEach(["15m", "1h", "6h", "24h"], id: \.self) { Text("Last \($0)").tag($0) } }.pickerStyle(.menu).fixedSize()
                    Picker("Kind", selection: $kind) { Text("All kinds").tag("all"); ForEach(KernelData.netlinkKinds, id: \.self) { Text($0.capitalized).tag($0) } }.pickerStyle(.menu).fixedSize()
                    Spacer()
                }.padding(.horizontal).padding(.bottom, 6)
                switch tab {
                case .events: events(rows, all: all)
                case .findings: findingList(findings)
                case .nodes: nodeHealth(nodes)
                }
            }
        }
        .searchable(text: $query, prompt: "Filter by node, interface, comm")
        .linkFilter(text: $query)
    }

    private func events(_ rows: [KernelData.NetlinkRow], all: [KernelData.NetlinkRow]) -> some View {
        let bins = KernelData.netlinkTimeline(all, binSeconds: since == "15m" ? 30 : since == "1h" ? 120 : since == "6h" ? 600 : 1800)
        return VStack(spacing: 0) {
            if !bins.isEmpty {
                Chart(bins) { b in BarMark(x: .value("Time", b.start), y: .value("Changes", b.count)).foregroundStyle(by: .value("Kind", b.kind)) }
                    .frame(height: 110).padding(.horizontal)
                    .accessibilityLabel("Netlink changes over time, by kind")
            }
            HSplitView {
                if rows.isEmpty { KernelEmpty(text: query.isEmpty ? "No changes recorded in this window." : "No matches", symbol: "arrow.triangle.branch") } else {
                    Table(rows, selection: $selection, sortOrder: $sort) {
                        TableColumn("When", value: \.timeSort) { r in Text(r.time.map { CellFormat.relative($0) } ?? "–").monospacedDigit() }.width(min: 80)
                        TableColumn("Node", value: \.node) { Text($0.node) }.width(min: 80)
                        TableColumn("Kind", value: \.kind) { r in Label(r.kind, systemImage: r.action == "delete" ? "minus.circle" : "plus.circle") }.width(min: 90)
                        TableColumn("Action", value: \.action) { Text($0.action) }.width(min: 50)
                        TableColumn("Interface", value: \.iface) { Text($0.iface) }.width(min: 70)
                        TableColumn("Change", value: \.subject) { Text($0.subject).lineLimit(1) }.width(min: 160)
                        TableColumn("Requester", value: \.requester) { r in
                            Label(r.requester, systemImage: r.origin == "process" ? "person.fill" : r.origin == "kernel" ? "cpu" : "questionmark.circle")
                        }.width(min: 120)
                        TableColumn("Cgroup", value: \.cgroupSort) { Text($0.cgroup.map(String.init) ?? "").monospacedDigit() }.width(min: 70)
                    }
                }
                Group {
                    if let r = rows.first(where: { $0.id == selection }) { KernelRawJSON(value: r.raw) }
                    else { ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select a change to inspect it.")) }
                }.frame(minWidth: 240, idealWidth: 300)
            }
        }
    }

    private func findingList(_ f: [KernelData.Finding]) -> some View {
        Group {
            if f.isEmpty { KernelEmpty(text: "No netlink findings right now.", symbol: "checkmark.circle") } else {
                List(f) { x in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack { SeverityLabel(severity: x.severity); Text(x.kind).fontWeight(.medium); Spacer(); Text(x.node).foregroundStyle(.secondary) }
                        Text(x.message).textSelection(.enabled)
                        if let l = x.lastObserved { Text("last seen \(CellFormat.relative(l))").font(.caption).foregroundStyle(.secondary) }
                    }.padding(.vertical, 3)
                }
            }
        }
    }

    private func nodeHealth(_ nodes: [KernelData.NetlinkNode]) -> some View {
        Group {
            if nodes.isEmpty { KernelEmpty(text: "No agents reporting.") } else {
                Table(nodes) {
                    TableColumn("Node") { n in Text(n.node + (n.stale ? " (stale)" : "")) }.width(min: 100)
                    TableColumn("Recorder") { n in
                        if !n.reporting { SeverityLabel(severity: .info, text: n.unavailable.isEmpty ? "Not reporting" : n.unavailable) }
                        else if n.lossy { SeverityLabel(severity: .warning, text: "Lost messages") }
                        else { SeverityLabel(severity: .ok, text: "Healthy") }
                    }.width(min: 150)
                    TableColumn("Dropped / missed / overruns") { Text("\($0.dropped) / \($0.missed) / \($0.overruns)").monospacedDigit() }.width(min: 160)
                    TableColumn("Resubscribes") { Text(String($0.resubscribes)).monospacedDigit() }.width(min: 80)
                    TableColumn("Attribution") { n in Text(n.actorAvailable ? "available" : (n.actorUnavailable.isEmpty ? "off" : n.actorUnavailable)) }.width(min: 100)
                    TableColumn("Links / addrs / routes / neigh") { Text("\($0.links) / \($0.addresses) / \($0.routes) / \($0.neighbors)").monospacedDigit() }.width(min: 190)
                    TableColumn("History since") { Text($0.historySince.map { CellFormat.relative($0) } ?? "–") }.width(min: 90)
                }
            }
        }
    }
}

extension KernelData.NetlinkRow {
    var timeSort: Date { time ?? .distantPast }
    var cgroupSort: Int { cgroup ?? 0 }
}
