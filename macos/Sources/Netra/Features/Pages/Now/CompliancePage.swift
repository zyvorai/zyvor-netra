// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// Compliance packs (CIS-style): pass/warn/fail per pack, a control table and evidence/remediation inspector.
struct CompliancePage: View {
    var body: some View {
        NowFetch(title: "Compliance", endpoint: "api/v1/compliance", query: [URLQueryItem(name: "limit", value: "500")], liveEvery: nil) { json in
            ComplianceBody(json: json)
        }
    }
}

private struct ComplianceBody: View {
    let json: JSONValue
    @State private var selection: ControlItem.ID?
    @State private var pack = "All"
    @State private var query = ""
    @State private var sort = [KeyPathComparator(\ControlItem.statusRank, order: .reverse)]

    private struct Slice: Identifiable { var id: String { pack + status }; let pack: String; let status: String; let n: Int }

    var body: some View {
        let packs = NowData.packSummaries(json)
        let all = NowData.controls(json)
        let shown = all.filter { (pack == "All" || $0.pack == pack) && (query.isEmpty || [$0.title, $0.cisRef, $0.evidence].contains { $0.localizedCaseInsensitiveContains(query) }) }.sorted(using: sort)
        let failed = packs.map(\.failed).reduce(0, +), warned = packs.map(\.warned).reduce(0, +), passed = packs.map(\.passed).reduce(0, +)
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                StatCard(title: "Passed", value: "\(passed)", symbol: "checkmark.circle.fill", tint: .green)
                StatCard(title: "Warnings", value: "\(warned)", symbol: "exclamationmark.triangle.fill", tint: .orange)
                StatCard(title: "Failed", value: "\(failed)", symbol: "xmark.octagon.fill", tint: .red)
                StatCard(title: "Nodes audited", value: String(Int(json.at("sysctlSummary.nodes")?.asDouble ?? 0)), symbol: "server.rack")
            }
            if let n = json.at("note")?.string, !n.isEmpty { Text(n).font(.caption).foregroundStyle(.secondary) }
            if !packs.isEmpty {
                GroupBox("Controls by pack") {
                    Chart(packs.flatMap { p in [Slice(pack: p.title, status: "Pass", n: p.passed), Slice(pack: p.title, status: "Warn", n: p.warned), Slice(pack: p.title, status: "Fail", n: p.failed)] }) {
                        BarMark(x: .value("Controls", $0.n), y: .value("Pack", $0.pack)).foregroundStyle(by: .value("Status", $0.status))
                    }
                    .chartForegroundStyleScale(["Pass": Color.green, "Warn": Color.orange, "Fail": Color.red])
                    .frame(height: CGFloat(packs.count) * 34 + 50)
                }
            }
            HStack {
                Picker("Pack", selection: $pack) { Text("All packs").tag("All"); ForEach(packs, id: \.id) { Text($0.title).tag($0.title) } }.frame(maxWidth: 280)
                TextField("Filter controls", text: $query).textFieldStyle(.roundedBorder).frame(maxWidth: 240)
                Spacer(); Text("\(shown.count) controls").foregroundStyle(.secondary)
            }
            if all.isEmpty {
                ContentUnavailableView("No compliance data", systemImage: "checkmark.seal", description: Text("No agents have reported yet."))
            } else {
                HSplitView {
                    Table(shown, selection: $selection, sortOrder: $sort) {
                        TableColumn("Status", value: \.statusRank) { c in NowBadge(severity: c.status, text: c.statusRaw.capitalized) }.width(min: 90)
                        TableColumn("Control", value: \.title).width(min: 200)
                        TableColumn("CIS", value: \.cisRef).width(min: 50)
                        TableColumn("Pack", value: \.pack).width(min: 100)
                        TableColumn("Nodes", value: \.nodes) { Text(String($0.nodes)).monospacedDigit() }.width(min: 50)
                    }.frame(minHeight: 300)
                    ControlDetail(item: shown.first { $0.id == selection }).frame(minWidth: 260, idealWidth: 340)
                }.frame(minHeight: 320)
            }
        }
        .linkFilter(text: $query)
    }
}

private struct ControlDetail: View {
    let item: ControlItem?
    var body: some View {
        if let item {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(item.title).font(.headline)
                    HStack { NowBadge(severity: item.status, text: item.statusRaw.capitalized)
                        if !item.severity.isEmpty { Text("Severity: \(item.severity)").font(.caption).foregroundStyle(.secondary) } }
                    if !item.evidence.isEmpty { GroupBox("Evidence") { Text(item.evidence).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) } }
                    if !item.remediation.isEmpty { GroupBox("Remediation") { Text(item.remediation).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) } }
                }.padding()
            }
        } else { ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select a control for evidence and remediation.")) }
    }
}

extension ControlItem { var statusRank: Int { status.rank } }
