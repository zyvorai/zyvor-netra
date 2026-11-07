// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// DNS: per-name board, tunneling/DGA/beaconing findings, and DoT/DoH sightings. Observe-only GETs.
struct DNSPage: View {
    enum Tab: String, CaseIterable { case board = "Board", findings = "Findings", encrypted = "Encrypted DNS" }
    @State private var tab: Tab = .board

    var body: some View {
        VStack(spacing: 0) {
            TrafficTabs(selection: $tab)
            switch tab {
            case .board: board
            case .findings: findings
            case .encrypted: encrypted
            }
        }
    }

    // GET /api/v1/dns/board: {queries, failures, rows:[{name,queries,responses,failures,failRate}]}
    private var board: some View {
        DataPageView(PageConfig(
            title: "DNS", endpoint: "api/v1/dns/board", query: [.init(name: "limit", value: "100")],
            rowsPath: "rows", idKeys: ["name"],
            columns: [
                .init(title: "Name", path: "name", width: 260), .init(title: "Queries", path: "queries", kind: .int, width: 80),
                .init(title: "Responses", path: "responses", kind: .int, width: 80), .init(title: "Failures", path: "failures", kind: .int, width: 80),
                .init(title: "Fail rate", path: "failRate", kind: .ratio, width: 80),
            ],
            stats: [
                .init(title: "Queries", symbol: "magnifyingglass") { CellFormat.text($0.at("queries") ?? .number(0), .int) },
                .init(title: "Failures", symbol: "xmark.octagon", tint: .red) { CellFormat.text($0.at("failures") ?? .number(0), .int) },
                .init(title: "Fail rate", symbol: "percent", tint: .orange) { v in
                    TrafficData.percent(v.at("failures")?.asDouble ?? 0, of: v.at("queries")?.asDouble ?? 0) },
                .init(title: "Names", symbol: "list.bullet") { String($0.rows(at: "rows").count) },
                .init(title: "Worst name", symbol: "exclamationmark.triangle", tint: .orange) { v in
                    TrafficData.dnsBars(v, top: 1).first.map { "\($0.label)" } ?? "" },
            ],
            liveEvery: 10, emptyText: "No DNS activity observed yet."
        )) { v in
            RankedBarsCard(title: TrafficData.sum(v, key: "failures") > 0 ? "Names by failures" : "Names by queries", bars: TrafficData.dnsBars(v), unit: "queries")
        }
    }

    // GET /api/v1/ebpf/dns-findings: {findings:[...], snapshot:{...}}; 409 when the detector is not enabled.
    private var findings: some View {
        DataPageView(PageConfig(
            title: "DNS findings", endpoint: "api/v1/ebpf/dns-findings",
            rowsPath: "findings", idKeys: ["id"],
            columns: [
                .init(title: "Severity", path: "severity", width: 80), .init(title: "Type", path: "type", width: 120),
                .init(title: "Domain", path: "domain", width: 200), .init(title: "Subdomain", path: "subdomain", width: 160),
                .init(title: "Score", path: "score", kind: .number(2), width: 60), .init(title: "Count", path: "count", kind: .int, width: 60),
                .init(title: "Workload", path: "workload", width: 140), .init(title: "Pod", path: "pod", width: 140),
                .init(title: "Node", path: "node", width: 100), .init(title: "Process", path: "comm", width: 90),
                .init(title: "Last seen", path: "lastSeen", kind: .time, width: 90), .init(title: "First seen", path: "firstSeen", kind: .time, width: 90),
                .init(title: "Signals", path: "signals", width: 200),
            ],
            stats: [
                .init(title: "Active findings", symbol: "exclamationmark.triangle.fill", tint: .orange) { CellFormat.text($0.at("snapshot.activeFindings") ?? .number(0), .int) },
                .init(title: "Queries seen", symbol: "magnifyingglass") { CellFormat.text($0.at("snapshot.queriesSeen") ?? .number(0), .int) },
                .init(title: "Domains tracked", symbol: "globe") { CellFormat.text($0.at("snapshot.domainsTracked") ?? .number(0), .int) },
                .init(title: "Critical", symbol: "exclamationmark.octagon.fill", tint: .red) { v in
                    String(v.rows(at: "findings").filter { $0.value["severity"]?.string == "critical" }.count) },
            ],
            liveEvery: 10, emptyText: "No suspicious DNS patterns (tunneling, DGA, beaconing, NXDOMAIN or SERVFAIL storms)."
        ))
    }

    // GET /api/v1/ebpf/encrypted-dns: {result:{hits:[...],count,dotCount,dohCount,capped}, note}
    private var encrypted: some View {
        DataPageView(PageConfig(
            title: "Encrypted DNS", endpoint: "api/v1/ebpf/encrypted-dns",
            rowsPath: "result.hits", idKeys: ["host", "destinationIp"],
            columns: [
                .init(title: "Kind", path: "kind", width: 60), .init(title: "Host", path: "host", width: 220),
                .init(title: "Destination", path: "destinationIp", width: 130), .init(title: "Port", path: "port", kind: .int, width: 60),
                .init(title: "Proto", path: "protocol", width: 60), .init(title: "Node", path: "node", width: 100),
                .init(title: "Namespace", path: "namespace", width: 110), .init(title: "Pod", path: "pod", width: 160),
                .init(title: "Packets", path: "packets", kind: .int, width: 70), .init(title: "Label", path: "label", width: 140),
            ],
            stats: [
                .init(title: "Sightings", symbol: "lock.shield") { CellFormat.text($0.at("result.count") ?? .number(0), .int) },
                .init(title: "DoT (853)", symbol: "lock") { CellFormat.text($0.at("result.dotCount") ?? .number(0), .int) },
                .init(title: "DoH", symbol: "lock.rotation") { CellFormat.text($0.at("result.dohCount") ?? .number(0), .int) },
                .init(title: "Catalog size", symbol: "books.vertical") { CellFormat.text($0.at("result.dohCatalogSize") ?? .number(0), .int) },
            ],
            liveEvery: 15, emptyText: "No encrypted DNS observed. DoT = port 853, DoH = known resolver hostnames; nothing is decrypted."
        )) { v in
            if v.at("result.capped") == .bool(true) {
                Label("Result list is capped; narrow by node or pod to see everything.", systemImage: "scissors").font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal).padding(.bottom, 6)
            }
        }
    }
}
