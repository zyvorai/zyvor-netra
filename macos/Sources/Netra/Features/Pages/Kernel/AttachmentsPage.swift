// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// GET /api/v1/ebpf/attachments (+ /ebpf/coverage): what the kernel reports attached on each node's
/// interfaces next to what the agent believes it attached. Strictly read-only: no attach, detach or replace.
struct AttachmentsPage: View {
    @State private var query = ""
    @State private var selection: String?
    @State private var tab = 0

    var body: some View {
        KernelLoader(title: "BPF attachments", endpoint: "api/v1/ebpf/attachments",
                     secondary: [("api/v1/ebpf/coverage", [])], liveEvery: 15) { v, extra in
            let nodes = KernelData.attachNodes(v)
            let findings = KernelData.findings(v)
            let rows = KernelData.attachRows(v).filter { query.isEmpty || [$0.node, $0.iface, $0.xdp, $0.tcxIngress, $0.tcxEgress, $0.tcIngress, $0.tcEgress].contains { $0.localizedCaseInsensitiveContains(query) } }
            let drift = nodes.filter(\.drift).count
            let detached = (extra.first ?? nil)?.at("detachedPrograms")?.asDouble
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        StatCard(title: "Nodes reporting", value: "\(nodes.filter(\.reporting).count) of \(nodes.count)", symbol: "server.rack")
                        StatCard(title: "Nodes with drift", value: String(drift), symbol: drift > 0 ? "exclamationmark.triangle.fill" : "checkmark.circle.fill", tint: drift > 0 ? .orange : .green)
                        StatCard(title: "Findings", value: String(findings.count), symbol: "doc.text.magnifyingglass", tint: findings.contains { $0.severity <= .warning } ? .orange : .blue)
                        StatCard(title: "Interfaces with programs", value: String(rows.count), symbol: "network")
                        StatCard(title: "Detached programs", value: detached.map { String(Int($0)) } ?? "", symbol: "link.badge.plus")
                        StatCard(title: "Evaluated / skipped", value: "\(v.at("evaluated")?.summary ?? "0") / \(v.at("skipped")?.summary ?? "0")", symbol: "checklist")
                    }.padding([.horizontal, .top])
                }.padding(.bottom, 8)
                Picker("View", selection: $tab) {
                    Text("Interfaces").tag(0); Text("Nodes and drift").tag(1); Text("Findings (\(findings.count))").tag(2)
                }.pickerStyle(.segmented).fixedSize().padding(.bottom, 6)
                switch tab {
                case 1: nodeList(nodes)
                case 2: findingList(findings)
                default: interfaceTable(rows)
                }
            }
        }
        .searchable(text: $query, prompt: "Filter interfaces and programs")
        .linkFilter(text: $query)
    }

    private func interfaceTable(_ rows: [KernelData.AttachRow]) -> some View {
        HSplitView {
            if rows.isEmpty { KernelEmpty(text: query.isEmpty ? "No programs attached on any reporting node." : "No matches") } else {
                Table(rows, selection: $selection) {
                    TableColumn("Node") { Text($0.node) }.width(min: 80)
                    TableColumn("Interface") { r in Text(r.iface).fontWeight(.medium) }.width(min: 80)
                    TableColumn("Type") { Text($0.type + ($0.state.isEmpty ? "" : " · \($0.state)")) }.width(min: 80)
                    TableColumn("XDP") { Text($0.xdp.isEmpty ? "–" : $0.xdp).lineLimit(1) }.width(min: 120)
                    TableColumn("TCX ingress") { Text($0.tcxIngress.isEmpty ? "–" : $0.tcxIngress).lineLimit(1) }.width(min: 160)
                    TableColumn("TCX egress") { Text($0.tcxEgress.isEmpty ? "–" : $0.tcxEgress).lineLimit(1) }.width(min: 160)
                    TableColumn("Owners") { r in Text("netra \(r.netra) · cilium \(r.cilium)" + (r.other > 0 ? " · other \(r.other)" : "")).monospacedDigit() }.width(min: 150)
                }
            }
            Group {
                if let r = rows.first(where: { $0.id == selection }) {
                    List {
                        Section("\(r.node) / \(r.iface)") {
                            LabeledContent("Index", value: String(r.index)); LabeledContent("Type", value: r.type); LabeledContent("State", value: r.state)
                        }
                        Section("Programs, in execution order") {
                            prog("XDP", r.xdp); prog("TCX ingress", r.tcxIngress); prog("TCX egress", r.tcxEgress)
                            prog("TC ingress (cls_bpf)", r.tcIngress); prog("TC egress (cls_bpf)", r.tcEgress)
                        }
                        Text("Cilium-owned programs are listed for visibility only; Netra never modifies them.").font(.caption).foregroundStyle(.secondary)
                    }
                } else { ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select an interface.")) }
            }.frame(minWidth: 240, idealWidth: 300)
        }
    }

    private func prog(_ label: String, _ text: String) -> some View {
        LabeledContent(label) { Text(text.isEmpty ? "none" : text).multilineTextAlignment(.trailing).textSelection(.enabled) }
    }

    private func nodeList(_ nodes: [KernelData.AttachNode]) -> some View {
        Group {
            if nodes.isEmpty { KernelEmpty(text: "No agents reporting.") } else {
                Table(nodes) {
                    TableColumn("Node") { n in Text(n.node + (n.stale ? " (stale)" : "")) }.width(min: 100)
                    TableColumn("Status") { n in
                        if n.drift { SeverityLabel(severity: .warning, text: "Drift") }
                        else if !n.reporting { SeverityLabel(severity: .info, text: "Not reporting") }
                        else { SeverityLabel(severity: .ok, text: "As expected") }
                    }.width(min: 110)
                    TableColumn("Missing Netra program on") { n in
                        Text(n.drift ? n.missing.joined(separator: ", ") : (n.reporting ? "–" : n.unavailable)).lineLimit(2)
                    }.width(min: 200)
                    TableColumn("Configured") { Text($0.configured.joined(separator: ", ")) }.width(min: 100)
                    TableColumn("Hooks") { Text($0.hooks.joined(separator: ", ")) }.width(min: 100)
                    TableColumn("Unreadable") { n in Text(n.failed.isEmpty ? "–" : n.failed.joined(separator: ", ")) }.width(min: 80)
                    TableColumn("TCX") { Text($0.tcxSupported ? "supported" : "kernel < 6.6: cannot list") }.width(min: 90)
                }
            }
        }
    }

    private func findingList(_ f: [KernelData.Finding]) -> some View {
        Group {
            if f.isEmpty { KernelEmpty(text: "No attachment drift findings.", symbol: "checkmark.circle") } else {
                Table(f) {
                    TableColumn("Severity") { SeverityLabel(severity: $0.severity) }.width(min: 90)
                    TableColumn("Node") { Text($0.node) }.width(min: 80)
                    TableColumn("Kind") { Text($0.kind) }.width(min: 100)
                    TableColumn("Message") { Text($0.message).lineLimit(3).textSelection(.enabled) }.width(min: 300)
                    TableColumn("Interfaces") { Text($0.interfaces.joined(separator: ", ")) }.width(min: 100)
                }
            }
        }
    }
}
