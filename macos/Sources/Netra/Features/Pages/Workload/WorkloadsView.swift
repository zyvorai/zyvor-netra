// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// Observed workload identities (namespace/pod/owner/node/cgroup) joined with pod lockdown state.
struct WorkloadsPage: View {
    var body: some View {
        WLPage(title: "Workloads", subtitle: "api/v1/ebpf/workloads", liveEvery: 10, load: { c in
            async let w = wlGET(c, "api/v1/ebpf/workloads")
            async let p = wlOptional(c, "api/v1/pods")      // optional: adds lockdown + readiness
            return .object(["workloads": try await w, "pods": await p ?? .null])
        }) { value, query in
            let rows = WorkloadData.workloadRows(workloads: value["workloads"], pods: value["pods"])
            let s = WorkloadData.workloadSummary(rows)
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        StatCard(title: "Pods", value: "\(s.pods)", symbol: "cube")
                        StatCard(title: "Workloads", value: "\(s.owners)", symbol: "shippingbox")
                        StatCard(title: "Namespaces", value: "\(s.namespaces)", symbol: "square.stack.3d.up")
                        StatCard(title: "Nodes", value: "\(s.nodes)", symbol: "server.rack")
                        StatCard(title: "Locked down", value: value["pods"] == .null ? "n/a" : "\(s.lockedDown)", symbol: "lock.fill", tint: s.lockedDown > 0 ? .red : .secondary)
                        StatCard(title: "No owner", value: "\(s.unowned)", symbol: "questionmark.circle", tint: .secondary)
                    }.padding([.horizontal, .top])
                }.padding(.bottom, 8)
                ChartRow {
                    BarCard(title: "Pods per namespace", data: WorkloadData.countBy(rows, path: "namespace").map { ($0.name, Double($0.count)) })
                    BarCard(title: "Pods per node", data: WorkloadData.countBy(rows, path: "node").map { ($0.name, Double($0.count)) }, tint: .teal)
                }
                WLTable(rows: rows, columns: [
                    WCol(title: "Namespace", path: "namespace", width: 90),
                    WCol(title: "Pod", path: "pod", width: 140),
                    WCol(title: "Workload", path: "owner", width: 110),
                    WCol(title: "Node", path: "node"),
                    WCol(title: "Lockdown", path: "lockedDownText", sortPath: "lockedDown", style: .lockedBadge, width: 100),
                    WCol(title: "Service account", path: "serviceAccountName"),
                ], query: query, empty: "No observed workloads. The agent attributes pods once Kubernetes metadata is available.") { row in
                    VStack(alignment: .leading, spacing: 12) {
                        if row.value["lockedDown"] == .bool(true) { LockedBadge() }
                        KVSection(title: "Identity", items: [
                            ("Namespace", CellFormat.text(row.value.at("namespace"), .text)),
                            ("Pod", CellFormat.text(row.value.at("pod"), .text)),
                            ("Workload", CellFormat.text(row.value.at("owner"), .text)),
                            ("Node", CellFormat.text(row.value.at("node"), .text)),
                            ("Service account", CellFormat.text(row.value.at("serviceAccountName"), .text)),
                            ("Cgroup ID", CellFormat.text(row.value.at("cgroupId"), .text)),
                        ])
                        let ns = row.value.at("namespace")?.string ?? "", pod = row.value.at("pod")?.string ?? ""
                        if !ns.isEmpty, !pod.isEmpty { WorkloadDetailView(kind: "pod", namespace: ns, name: pod, allowLogs: false) }
                        LabelsView(pairs: WorkloadData.labelPairs(row.value.at("labels")))
                        RawJSON(value: row.value)
                    }
                }
            }
        }
    }
}

/// Read-only /api/v1/workloads/{kind}/{ns}/{name}: matching policies, recommended selector, containers.
struct WorkloadDetailView: View {
    let kind: String, namespace: String, name: String
    var allowLogs: Bool
    @Environment(AppModel.self) private var model
    @State private var detail: JSONValue?
    @State private var error: String?
    @State private var showLogs = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let d = detail {
                if d["lockedDown"] == .bool(true) {
                    LockedBadge()
                    if let p = d["lockdownPolicy"]?.string { Text("Lockdown policy: \(p)").font(.caption).foregroundStyle(.secondary) }
                }
                KVSection(title: "Runtime", items: [
                    ("Phase", CellFormat.text(d["phase"], .text)),
                    ("Ready", CellFormat.text(d["ready"], .bool)),
                    ("Pod IP", CellFormat.text(d["podIP"], .text)),
                    ("Node", CellFormat.text(d["node"], .text)),
                    ("Owner", [d["ownerKind"]?.string, d["ownerName"]?.string].compactMap { $0 }.joined(separator: "/")),
                ])
                GroupBox("Policies (\(WorkloadData.items(d, "policies").count))") {
                    let pols = WorkloadData.items(d, "policies")
                    VStack(alignment: .leading, spacing: 4) {
                        if pols.isEmpty { Text("No NetworkPolicy selects this workload.").font(.caption).foregroundStyle(.secondary) }
                        ForEach(Array(pols.enumerated()), id: \.offset) { _, p in
                            HStack {
                                Text(p["name"]?.string ?? "?").font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                                if p["lockdown"] == .bool(true) { Text("lockdown").font(.caption2).foregroundStyle(.red) }
                            }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
                LabelsView(pairs: WorkloadData.labelPairs(d["recommendedSelector"]), title: "Recommended selector")
                let cs = WorkloadData.items(d, "containers")
                if !cs.isEmpty {
                    GroupBox("Containers") {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(Array(cs.enumerated()), id: \.offset) { _, c in
                                HStack {
                                    Label(c["name"]?.string ?? "?", systemImage: c["ready"] == .bool(true) ? "checkmark.circle" : "exclamationmark.triangle")
                                        .foregroundStyle(c["ready"] == .bool(true) ? .green : .orange)
                                    Spacer()
                                    Text("restarts \(CellFormat.text(c["restartCount"], .int).isEmpty ? "0" : CellFormat.text(c["restartCount"], .int))").font(.caption).monospacedDigit().foregroundStyle(.secondary)
                                }.font(.caption)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                if allowLogs { Button("View logs", systemImage: "doc.text.magnifyingglass") { showLogs = true } }
            } else if let error {
                Label(error, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
            } else { ProgressView().controlSize(.small) }
        }
        .task(id: "\(kind)/\(namespace)/\(name)") { await load() }
        .sheet(isPresented: $showLogs) {
            PodLogsView(namespace: namespace, name: name, containers: WorkloadData.items(detail, "containers").compactMap { $0["name"]?.string })
        }
    }

    private func load() async {
        detail = nil; error = nil
        guard let c = model.client else { return }
        do { detail = try await wlGET(c, WorkloadData.detailPath(kind: kind, namespace: namespace, name: name)) }
        catch NetraError.http(let s, let m) { error = "Detail unavailable (HTTP \(s)): \(m)" }
        catch { self.error = error.localizedDescription }
    }
}

/// Read-only snapshot of a pod's recent log lines (GET .../logs?follow=false). Log text is shown as-is
/// and never stored or forwarded by this client. The server may refuse when its console feature is off.
struct PodLogsView: View {
    let namespace: String, name: String, containers: [String]
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var container = ""
    @State private var tail = 200
    @State private var lines: [String] = []
    @State private var error: String?
    @State private var loading = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Logs: \(namespace)/\(name)").font(.headline)
                Spacer()
                if containers.count > 1 {
                    Picker("Container", selection: $container) { ForEach(containers, id: \.self) { Text($0).tag($0) } }.frame(maxWidth: 220)
                }
                Picker("Lines", selection: $tail) { ForEach([100, 200, 500, 1000], id: \.self) { Text("\($0)").tag($0) } }.frame(width: 120)
                Button("Reload", systemImage: "arrow.clockwise") { Task { await load() } }.disabled(loading)
                Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            if let error { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.caption) }
            ScrollView {
                Text(lines.isEmpty && !loading ? "No log lines." : lines.joined(separator: "\n"))
                    .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }.background(.background.secondary, in: RoundedRectangle(cornerRadius: 6))
        }
        .padding().frame(minWidth: 720, minHeight: 440)
        .task(id: "\(container)-\(tail)") { await load() }
        .onAppear { if container.isEmpty { container = containers.first ?? "" } }
    }

    private func load() async {
        guard let c = model.client else { return }
        loading = true; defer { loading = false }
        var q = [URLQueryItem(name: "follow", value: "false"), URLQueryItem(name: "tailLines", value: "\(tail)")]
        if !container.isEmpty { q.append(URLQueryItem(name: "container", value: container)) }
        var req = c.request("GET", WorkloadData.logsPath(namespace: namespace, name: name), query: q)
        req.timeoutInterval = 30
        do {
            let r = WorkloadData.parseLogStream(try await c.send(req))
            lines = r.lines; error = r.error
        } catch NetraError.http(let s, let m) { error = "HTTP \(s): \(m)" }
        catch { self.error = error.localizedDescription }
    }
}
