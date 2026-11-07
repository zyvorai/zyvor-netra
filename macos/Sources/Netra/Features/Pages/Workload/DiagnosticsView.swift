// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// Network diagnostics: policy-drop detective, TCP path pressure and connect latency, IPv6 extension headers
/// and kernel-network findings. Read-only: suggested sysctl commands are shown as guidance and never applied.
struct DiagnosticsPage: View {
    var body: some View {
        WLPage(title: "Diagnostics", subtitle: "api/v1/ebpf/diagnose", liveEvery: 5, load: { c in
            async let d = wlGET(c, "api/v1/ebpf/diagnose", [URLQueryItem(name: "limit", value: "200")])
            async let p = wlOptional(c, "api/v1/ebpf/path", [URLQueryItem(name: "limit", value: "200")])
            async let v6 = wlOptional(c, "api/v1/ebpf/ipv6", [URLQueryItem(name: "limit", value: "100")])
            async let k = wlOptional(c, "api/v1/ebpf/kernel-network", [URLQueryItem(name: "window", value: "5m")])
            return .object(["drops": try await d, "path": await p ?? .null, "ipv6": await v6 ?? .null, "kernel": await k ?? .null])
        }) { value, query in DiagnosticsBody(value: value, query: query) }
    }
}

private struct DiagnosticsBody: View {
    let value: JSONValue
    let query: String
    enum Tab: String, CaseIterable { case drops = "Policy drops", pressure = "TCP pressure", connect = "Connect latency", ipv6 = "IPv6", kernel = "Kernel", anomalies = "Anomalies" }
    @State private var tab = Tab.drops

    var body: some View {
        let drops = WorkloadData.detectiveRows(value["drops"])
        let pressure = WorkloadData.pressureRows(value["path"])
        let connect = WorkloadData.connectRows(value["path"])
        let ipv6 = WorkloadData.ipv6Rows(value["ipv6"])
        let kernel = WorkloadData.kernelFindingRows(value["kernel"])
        let anomalies = WorkloadData.anomalyRows(value["path"]) + WorkloadData.anomalyRows(value["ipv6"])
        let ds = value["drops"]?["summary"], ps = value["path"]?["summary"], ks = value["kernel"]?["summary"]
        let worst = max(WorkloadData.worstLevel(kernel), WorkloadData.worstLevel(anomalies))
        let unavailable = [("path", "TCP path"), ("ipv6", "IPv6"), ("kernel", "Kernel")].filter { value[$0.0] == .null }.map(\.1)
        VStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 10) {
                    StatCard(title: "Health", value: worst.label, symbol: worst.symbol, tint: worst.tint)
                    StatCard(title: "Dropped packets", value: CellFormat.text(ds?.at("policyDropPackets"), .int), symbol: "nosign", tint: WorkloadData.num(ds, "policyDropPackets") > 0 ? .orange : .secondary)
                    StatCard(title: "Exact / probable", value: "\(Int(WorkloadData.num(ds, "exactFindings"))) / \(Int(WorkloadData.num(ds, "probableFindings")))", symbol: "scope")
                    StatCard(title: "Congested flows", value: CellFormat.text(ps?.at("congestedFlows"), .int), symbol: "tortoise", tint: WorkloadData.num(ps, "congestedFlows") > 0 ? .orange : .secondary)
                    StatCard(title: "Retransmits", value: CellFormat.text(ps?.at("totalRetrans"), .int), symbol: "arrow.triangle.2.circlepath")
                    StatCard(title: "Avg connect", value: CellFormat.text(.number(WorkloadData.num(ps, "averageConnectUs") / 1000), .millis), symbol: "timer")
                    StatCard(title: "Kernel crit / warn", value: "\(Int(WorkloadData.num(ks, "critical"))) / \(Int(WorkloadData.num(ks, "warnings")))", symbol: "cpu",
                             tint: WorkloadData.num(ks, "critical") > 0 ? .red : WorkloadData.num(ks, "warnings") > 0 ? .orange : .secondary)
                }.padding([.horizontal, .top])
            }.padding(.bottom, 8)
            if !unavailable.isEmpty {
                Label("Unavailable: \(unavailable.joined(separator: ", ")). Those tabs stay empty.", systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal).padding(.bottom, 6)
            }
            ChartRow {
                BarCard(title: "Drops by reason (packets)", data: Dictionary(grouping: drops, by: { WorkloadData.str($0.value, "code") })
                    .map { ($0.key, $0.value.reduce(0) { $0 + WorkloadData.num($1.value, "packets") }) }.sorted { $0.1 > $1.1 }.prefix(6).map { $0 }, tint: .orange)
                BarCard(title: "Slowest connects (mean)", data: connect.sorted { WorkloadData.num($0.value, "avgMs") > WorkloadData.num($1.value, "avgMs") }.prefix(5)
                    .map { (WorkloadData.str($0.value, "remote"), WorkloadData.num($0.value, "avgMs")) }, tint: .purple, unit: { String(format: "%.1f ms", $0) })
            }
            WLTabs(selection: $tab)
            switch tab {
            case .drops:
                WLTable(rows: drops, columns: [
                    WCol(title: "Confidence", path: "level", sortPath: "levelRank", style: .level, width: 90),
                    WCol(title: "Reason", path: "code", width: 110), WCol(title: "Dir", path: "directionName"), WCol(title: "Proto", path: "protocolName"),
                    WCol(title: "Source", path: "src", width: 130), WCol(title: "Destination", path: "dst", width: 130),
                    WCol(title: "Packets", path: "packets", kind: .int), WCol(title: "Bytes", path: "bytes", kind: .bytes),
                    WCol(title: "Workload", path: "workload", width: 130), WCol(title: "Process", path: "comm"), WCol(title: "Node", path: "node"),
                ], query: query, empty: "No policy drops observed.") { row in
                    VStack(alignment: .leading, spacing: 12) {
                        Text(WorkloadData.str(row.value, "explanation")).font(.callout).textSelection(.enabled)
                        if !WorkloadData.str(row.value, "suggestion").isEmpty {
                            GroupBox("Suggestion") { Text(WorkloadData.str(row.value, "suggestion")).font(.callout).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                        }
                        KVSection(title: "Flow", items: [
                            ("Confidence", WorkloadData.str(row.value, "confidence")), ("Stage", WorkloadData.str(row.value, "stage")),
                            ("Source", WorkloadData.str(row.value, "src")), ("Destination", WorkloadData.str(row.value, "dst")),
                            ("Attribution", WorkloadData.str(row.value, "attributionState")),
                        ])
                        RawJSON(value: row.value)
                    }
                }
            case .pressure:
                WLTable(rows: pressure, columns: [
                    WCol(title: "Remote", path: "remote", width: 140), WCol(title: "Workload", path: "workload", width: 130),
                    WCol(title: "Cwnd use", path: "cwndUse", kind: .ratio), WCol(title: "Cwnd", path: "sendCwnd", kind: .int),
                    WCol(title: "Out", path: "packetsOut", kind: .int), WCol(title: "Retrans out", path: "retransOut", kind: .int),
                    WCol(title: "Lost", path: "lostOut", kind: .int), WCol(title: "Total retrans", path: "totalRetrans", kind: .int),
                ], query: query, empty: "No TCP pressure samples.", fields: [
                    WField(label: "Remote", path: "remote"), WField(label: "Workload", path: "workload"), WField(label: "Cwnd", path: "sendCwnd", kind: .int),
                    WField(label: "Ssthresh", path: "sendSsthresh", kind: .int), WField(label: "Packets out", path: "packetsOut", kind: .int),
                    WField(label: "Sacked", path: "sackedOut", kind: .int), WField(label: "MSS", path: "mss", kind: .int),
                ])
            case .connect:
                WLTable(rows: connect, columns: [
                    WCol(title: "Remote", path: "remote", width: 140), WCol(title: "Workload", path: "workload", width: 130),
                    WCol(title: "Connections", path: "established", kind: .int), WCol(title: "Mean", path: "avgMs", kind: .millis), WCol(title: "Max", path: "maxMs", kind: .millis),
                ], query: query, empty: "No connect latency samples.", fields: [
                    WField(label: "Remote", path: "remote"), WField(label: "Workload", path: "workload"), WField(label: "Established", path: "established", kind: .int),
                    WField(label: "Mean", path: "avgMs", kind: .millis), WField(label: "Max", path: "maxMs", kind: .millis),
                ])
            case .ipv6:
                WLTable(rows: ipv6, columns: [
                    WCol(title: "Node", path: "node"), WCol(title: "Hook", path: "hook"), WCol(title: "Dir", path: "direction"),
                    WCol(title: "Packets", path: "packets", kind: .int), WCol(title: "Ext hdr pkts", path: "extHeaderPackets", kind: .int),
                    WCol(title: "Fragmented", path: "fragmented", kind: .int), WCol(title: "Fragment %", path: "fragmentRatio", kind: .ratio),
                    WCol(title: "Truncated", path: "chainTruncated", kind: .int),
                ], query: query, empty: "No IPv6 extension-header traffic recorded.", fields: [
                    WField(label: "Node", path: "node"), WField(label: "Hook", path: "hook"), WField(label: "Total ext headers", path: "totalExtHeaders", kind: .int),
                    WField(label: "Non-first fragments", path: "nonFirstFragments", kind: .int), WField(label: "More fragments", path: "moreFragments", kind: .int),
                    WField(label: "Chain truncated", path: "chainTruncated", kind: .int),
                ])
            case .kernel:
                WLTable(rows: kernel, columns: [
                    WCol(title: "Severity", path: "level", sortPath: "levelRank", style: .level, width: 90),
                    WCol(title: "Node", path: "node"), WCol(title: "Layer", path: "layer"), WCol(title: "Signal", path: "signal", width: 160),
                    WCol(title: "Tunable", path: "tunable", width: 130), WCol(title: "Now", path: "currentValue"), WCol(title: "Suggested", path: "suggestedValue"),
                    WCol(title: "Risk", path: "risk"),
                ], query: query, empty: "No kernel-network findings.") { row in
                    VStack(alignment: .leading, spacing: 12) {
                        Text(WorkloadData.str(row.value, "explanation")).font(.callout).textSelection(.enabled)
                        GroupBox("Recommendation") { Text(WorkloadData.str(row.value, "recommendation")).font(.callout).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                        if !WorkloadData.str(row.value, "evidenceText").isEmpty {
                            GroupBox("Evidence") { Text(WorkloadData.str(row.value, "evidenceText")).font(.caption).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                        }
                        if !WorkloadData.str(row.value, "applyCommand").isEmpty {
                            GroupBox("Guidance only (Netra never applies this)") {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(WorkloadData.str(row.value, "applyCommand")).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                                    Text("Rollback: " + WorkloadData.str(row.value, "rollbackCommand")).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                                }.frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        RawJSON(value: row.value)
                    }
                }
            case .anomalies:
                WLTable(rows: anomalies, columns: [
                    WCol(title: "Severity", path: "level", sortPath: "levelRank", style: .level, width: 90),
                    WCol(title: "Kind", path: "kind", width: 120), WCol(title: "Subject", path: "subject", width: 160), WCol(title: "Message", path: "message", width: 260),
                ], query: query, empty: "No anomalies flagged on the TCP path or IPv6 walker.", fields: [
                    WField(label: "Severity", path: "level"), WField(label: "Kind", path: "kind"), WField(label: "Subject", path: "subject"),
                    WField(label: "Message", path: "message"), WField(label: "Value", path: "value", kind: .number(2)),
                ])
            }
        }
    }
}
