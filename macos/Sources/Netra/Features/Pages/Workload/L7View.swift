// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// L7 metadata: TLS SNI, cleartext HTTP/1 method+Host, HTTP/1 status codes, connection attempts and sampled
/// protocol counts. Metadata only: no payloads, headers or bodies are requested or shown.
struct L7Page: View {
    var body: some View {
        WLPage(title: "L7", subtitle: "api/v1/ebpf/l7", liveEvery: 5, load: { c in
            async let l7 = wlGET(c, "api/v1/ebpf/l7", [URLQueryItem(name: "limit", value: "500")])
            async let sampled = wlOptional(c, "api/v1/l7/sampled")
            return .object(["l7": try await l7, "sampled": await sampled ?? .null])
        }) { value, query in L7Body(value: value, query: query) }
    }
}

private struct L7Body: View {
    let value: JSONValue
    let query: String
    enum Tab: String, CaseIterable { case tls = "TLS SNI", http = "HTTP hosts", status = "HTTP status", conns = "Connections", sampled = "Sampled protocols" }
    @State private var tab = Tab.tls

    private func named(_ path: String) -> [(name: String, value: Double)] {
        WorkloadData.items(value["l7"], path).map { (WorkloadData.str($0, "name"), WorkloadData.num($0, "count")) }.prefix(8).map { $0 }
    }

    var body: some View {
        let l7 = value["l7"]
        let sum = l7?["summary"]
        let statusRows = WorkloadData.items(l7, "httpStatus")
        let n: (String) -> Double = { sum?.at($0)?.asDouble ?? 0 }
        let degradedHint = n("httpRequests") == 0 && n("tlsHandshakes") == 0 && n("connectAttempts") == 0
        VStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 10) {
                    StatCard(title: "TLS handshakes", value: "\(Int(n("tlsHandshakes")))", symbol: "lock")
                    StatCard(title: "Unique SNI", value: "\(Int(n("uniqueSni")))", symbol: "globe")
                    StatCard(title: "HTTP/1 requests", value: "\(Int(n("httpRequests")))", symbol: "arrow.left.arrow.right")
                    StatCard(title: "HTTP/1 5xx", value: "\(Int(n("http5xx")))", symbol: "exclamationmark.triangle", tint: n("http5xx") > 0 ? .red : .secondary)
                    StatCard(title: "HTTP hosts", value: "\(Int(n("uniqueHttpHosts")))", symbol: "server.rack")
                    StatCard(title: "Blocked / attempts", value: "\(Int(n("connectBlocked"))) / \(Int(n("connectAttempts")))", symbol: "nosign", tint: n("connectBlocked") > 0 ? .orange : .secondary)
                }.padding([.horizontal, .top])
            }.padding(.bottom, 8)
            if degradedHint {
                Label("No L7 activity reported. A quiet feed can also mean the L7 BPF programs failed to load on a node.", systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal).padding(.bottom, 6)
            }
            ChartRow {
                BarCard(title: "HTTP/1 status classes", data: WorkloadData.httpStatusClasses(statusRows).map { ($0.name, $0.count) }, tint: n("http5xx") > 0 ? .orange : .green)
                BarCard(title: "Top SNI (handshakes)", data: named("summary.topSni"))
                BarCard(title: "Top remote ports", data: named("summary.topRemotePorts"), tint: .teal)
            }
            WLTabs(selection: $tab)
            switch tab {
            case .tls:
                WLTable(rows: WorkloadData.l7Rows(WorkloadData.items(l7, "tls"), totalKey: "handshakes"), columns: [
                    WCol(title: "SNI", path: "sni", width: 180), WCol(title: "Handshakes", path: "handshakes", kind: .int),
                    WCol(title: "Blocked", path: "blocked", kind: .int), WCol(title: "Blocked %", path: "blockedRatio", kind: .ratio),
                    WCol(title: "Workload", path: "workload", width: 140),
                ], query: query, empty: "No TLS ClientHello SNI observed.", fields: [
                    WField(label: "SNI", path: "sni"), WField(label: "Handshakes", path: "handshakes", kind: .int), WField(label: "Blocked", path: "blocked", kind: .int),
                    WField(label: "Workload", path: "workload"), WField(label: "Cgroup ID", path: "cgroupId"),
                ])
            case .http:
                WLTable(rows: WorkloadData.l7Rows(WorkloadData.items(l7, "http")), columns: [
                    WCol(title: "Method", path: "method"), WCol(title: "Host", path: "host", width: 180),
                    WCol(title: "Requests", path: "requests", kind: .int), WCol(title: "Workload", path: "workload", width: 140),
                ], query: query, empty: "No cleartext HTTP/1 requests observed.", fields: [
                    WField(label: "Method", path: "method"), WField(label: "Host", path: "host"),
                    WField(label: "Requests", path: "requests", kind: .int), WField(label: "Workload", path: "workload"),
                ])
            case .status:
                WLTable(rows: WorkloadData.l7Rows(statusRows), columns: [
                    WCol(title: "Status", path: "status", kind: .int), WCol(title: "Class", path: "statusClass"),
                    WCol(title: "Count", path: "count", kind: .int), WCol(title: "Workload", path: "workload", width: 140),
                ], query: query, empty: "No HTTP/1 status lines observed (HTTP/2, HTTP/3 and TLS are not decoded).", fields: [
                    WField(label: "Status", path: "status", kind: .int), WField(label: "Count", path: "count", kind: .int), WField(label: "Workload", path: "workload"),
                ])
            case .conns:
                WLTable(rows: WorkloadData.l7Rows(WorkloadData.items(l7, "connections"), totalKey: "attempts"), columns: [
                    WCol(title: "Proto", path: "protocol"), WCol(title: "Remote IP", path: "remoteIp", width: 120), WCol(title: "Port", path: "remotePort", kind: .int),
                    WCol(title: "Attempts", path: "attempts", kind: .int), WCol(title: "Blocked", path: "blocked", kind: .int),
                    WCol(title: "Blocked %", path: "blockedRatio", kind: .ratio), WCol(title: "Workload", path: "workload", width: 140),
                ], query: query, empty: "No connection attempts recorded.", fields: [
                    WField(label: "Protocol", path: "protocol"), WField(label: "Remote IP", path: "remoteIp"), WField(label: "Remote port", path: "remotePort"),
                    WField(label: "Attempts", path: "attempts", kind: .int), WField(label: "Blocked", path: "blocked", kind: .int), WField(label: "Workload", path: "workload"),
                ])
            case .sampled:
                SampledView(sampled: value["sampled"], query: query)
            }
        }
    }
}

private struct SampledView: View {
    let sampled: JSONValue?
    let query: String
    var body: some View {
        if sampled == nil || sampled == .null {
            ContentUnavailableView("Sampled protocols unavailable", systemImage: "text.bubble", description: Text("api/v1/l7/sampled did not respond."))
        } else {
            let rows = WorkloadData.sampledProtocolRows(sampled)
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    StatCard(title: "Nodes reporting", value: CellFormat.text(sampled?.at("nodesReporting"), .int), symbol: "checkmark.circle", tint: .green)
                    StatCard(title: "Not reporting", value: CellFormat.text(sampled?.at("nodesNotReporting"), .int), symbol: "minus.circle", tint: .secondary)
                    StatCard(title: "Scale factor", value: CellFormat.text(sampled?.at("scaleFactor"), .number(1)), symbol: "scalemass")
                    Spacer()
                }.padding(.horizontal).padding(.bottom, 8)
                Text("Counts are rate-limited samples; estimates multiply by the scale factor. Served and issued roles see the same request once each, so never add them together.")
                    .font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal).padding(.bottom, 6)
                ChartRow { BarCard(title: "Top operations (estimated requests)", data: WorkloadData.sampledTopOps(sampled).map { ($0.label, $0.estimated) }, tint: .indigo) }
                WLTable(rows: rows, columns: [
                    WCol(title: "Protocol", path: "name", width: 140), WCol(title: "Requests", path: "requests", kind: .int),
                    WCol(title: "Est. requests", path: "estimatedRequests", kind: .int), WCol(title: "Responses", path: "responses", kind: .int),
                    WCol(title: "Errors", path: "errors", kind: .int), WCol(title: "Error %", path: "errorRatio", kind: .ratio),
                ], query: query, empty: "No sampled protocols. Sampling is off or nothing matched a configured port.") { row in
                    VStack(alignment: .leading, spacing: 12) {
                        KVSection(title: "Protocol", items: [
                            ("Protocol", CellFormat.text(row.value.at("protocol"), .text)), ("Role", CellFormat.text(row.value.at("role"), .text)),
                            ("Requests", CellFormat.text(row.value.at("requests"), .int)), ("Errors", CellFormat.text(row.value.at("errors"), .int)),
                        ])
                        let ops = WorkloadData.items(row.value, "ops")
                        if !ops.isEmpty {
                            GroupBox("Operations") {
                                VStack(spacing: 3) {
                                    ForEach(Array(ops.enumerated()), id: \.offset) { _, o in
                                        HStack { Text(WorkloadData.str(o, "op")).font(.system(.caption, design: .monospaced)); Spacer(); Text(CellFormat.text(o["count"], .int)).monospacedDigit().font(.caption) }
                                    }
                                }
                            }
                        }
                        let codes = WorkloadData.items(row.value, "codes")
                        if !codes.isEmpty {
                            GroupBox("Response codes") {
                                VStack(spacing: 3) {
                                    ForEach(Array(codes.enumerated()), id: \.offset) { _, c in
                                        HStack {
                                            Label(WorkloadData.str(c, "code"), systemImage: WorkloadData.str(c, "status") == "error" ? "xmark.circle" : "checkmark.circle")
                                                .foregroundStyle(WorkloadData.str(c, "status") == "error" ? .red : .green).font(.caption)
                                            Spacer(); Text(CellFormat.text(c["count"], .int)).monospacedDigit().font(.caption)
                                        }
                                    }
                                }
                            }
                        }
                        RawJSON(value: row.value)
                    }
                }
            }
        }
    }
}
