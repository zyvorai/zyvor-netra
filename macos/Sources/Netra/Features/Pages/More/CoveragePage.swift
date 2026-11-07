// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// eBPF coverage (read-only). GET /api/v1/ebpf/coverage: {generatedAt, nodes:[{node,stale,mode,ageSeconds,hooks,programs:[{name,type,attached,runCount}],
/// attached,detached,missingMaps,hookCount,programCount}], agentCount, staleAgents, detachedPrograms, missingMapEntries, quiet}.
/// Plus GET /ebpf/capabilities {standalone,ciliumRequired,hubbleOptional,limits,hooks,observability,enforcement},
/// GET /ebpf/interfaces {nodes:[{node,interfaces:[{interface,packets,bytes,blocked,topDestinations}]}]}, GET /ebpf/summary.
struct MoreCoveragePage: View {
    enum Tab: String, CaseIterable { case nodes = "Nodes", programs = "Programs", interfaces = "Interfaces", capabilities = "Capabilities", summary = "Summary" }
    @State private var tab: Tab = .nodes

    var body: some View {
        MoreLoader(title: "eBPF coverage", endpoint: "api/v1/ebpf/coverage",
                   secondary: [("api/v1/ebpf/capabilities", []), ("api/v1/ebpf/interfaces", [.init(name: "limit", value: "50")]), ("api/v1/ebpf/summary", [])],
                   liveEvery: 10) { cov, extra in
            VStack(spacing: 0) {
                StatRow(stats: [
                    .init(title: "Agents", symbol: "server.rack") { CellFormat.text($0.at("agentCount") ?? .number(0), .int) },
                    .init(title: "Stale", symbol: "clock.badge.exclamationmark", tint: .orange) { CellFormat.text($0.at("staleAgents") ?? .number(0), .int) },
                    .init(title: "Detached programs", symbol: "bolt.slash", tint: .red) { CellFormat.text($0.at("detachedPrograms") ?? .number(0), .int) },
                    .init(title: "Missing maps", symbol: "map", tint: .red) { CellFormat.text($0.at("missingMapEntries") ?? .number(0), .int) },
                ], value: cov).padding([.horizontal, .top])
                TrafficTabs(selection: $tab)
                switch tab {
                case .nodes:
                    MoreRowsTable(rows: MoreData.joined(MoreData.joined(cov.rows(at: "nodes", idKeys: ["node"]), key: "detached"), key: "missingMaps"), columns: [
                        .init(title: "Node", path: "node", width: 140), .init(title: "Mode", path: "mode", width: 80), .init(title: "Stale", path: "stale", kind: .bool, width: 55),
                        .init(title: "Age", path: "ageSeconds", kind: .seconds, width: 70), .init(title: "Attached", path: "attached", kind: .int, width: 70),
                        .init(title: "Programs", path: "programCount", kind: .int, width: 70), .init(title: "Hooks", path: "hookCount", kind: .int, width: 55),
                        .init(title: "Detached", path: "detachedText", width: 200), .init(title: "Missing maps", path: "missingMapsText", width: 200),
                    ], empty: "No agents have reported.")
                case .programs:
                    MoreRowsTable(rows: MoreData.nested(cov, child: "programs"), columns: [
                        .init(title: "Node", path: "node", width: 130), .init(title: "Program", path: "name", width: 200), .init(title: "Type", path: "type", width: 110),
                        .init(title: "Attached", path: "attached", kind: .bool, width: 70), .init(title: "Runs", path: "runCount", kind: .int, width: 90),
                    ], empty: "No program inventory reported.")
                case .interfaces:
                    if let i = extra[1] {
                        MoreRowsTable(rows: MoreData.nested(i, child: "interfaces"), columns: [
                            .init(title: "Node", path: "node", width: 130), .init(title: "Interface", path: "interface", width: 110),
                            .init(title: "Packets", path: "packets", kind: .int, width: 90), .init(title: "Bytes", path: "bytes", kind: .bytes, width: 90),
                            .init(title: "Blocked", path: "blocked", kind: .int, width: 80),
                        ], empty: "No per-interface flow data (needs the TCX/XDP observer).")
                    } else { KernelEmpty(text: "Interface flows are unavailable.") }
                case .capabilities: capabilities(extra[0])
                case .summary: summary(extra[2])
                }
            }
        }
    }

    @ViewBuilder private func capabilities(_ c: JSONValue?) -> some View {
        if let c {
            ScrollView {
                VStack(spacing: 8) {
                    KVSection(title: "Mode", items: [("Standalone", CellFormat.text(c["standalone"], .bool)), ("Cilium required", CellFormat.text(c["ciliumRequired"], .bool)),
                                                     ("Hubble optional", CellFormat.text(c["hubbleOptional"], .bool))])
                    MoreBullets(title: "Hooks", items: MoreData.strings(c, at: "hooks"))
                    MoreBullets(title: "Observability", items: MoreData.strings(c, at: "observability"))
                    MoreBullets(title: "Enforcement (leased, fails open)", items: MoreData.strings(c, at: "enforcement"))
                    KVSection(title: "Map limits", items: c.mapRows(at: "limits").map { (label: $0.id, value: CellFormat.text($0.value["value"], .int)) })
                }.padding()
            }
        } else { KernelEmpty(text: "Capabilities are unavailable.") }
    }

    @ViewBuilder private func summary(_ s: JSONValue?) -> some View {
        if let s {
            ScrollView {
                VStack(spacing: 8) {
                    KVSection(title: "Totals", items: ["events", "blocked", "dnsQueries", "socketEvents", "packets"].map { (label: $0, value: CellFormat.text(s[$0], .int)) } +
                              [(label: "bytes", value: CellFormat.text(s["bytes"], .bytes))])
                    HStack(alignment: .top) {
                        namedCounts("Block reasons", s, "blockReasons"); namedCounts("Top destinations", s, "topDestinations")
                    }
                    HStack(alignment: .top) {
                        namedCounts("Top processes", s, "topProcesses"); namedCounts("Top DNS", s, "topDns")
                    }
                }.padding()
            }
        } else { KernelEmpty(text: "Summary is unavailable.") }
    }

    private func namedCounts(_ title: String, _ s: JSONValue, _ path: String) -> some View {
        KVSection(title: title, items: s.rows(at: path).prefix(10).map { (label: $0.value["name"]?.string ?? "?", value: CellFormat.text($0.value["count"], .int)) })
    }
}
