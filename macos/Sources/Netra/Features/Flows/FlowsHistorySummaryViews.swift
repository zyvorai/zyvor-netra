// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

struct FlowsHistoryView: View {
    @Environment(AppModel.self) private var model
    @State private var since = "1h"
    @State private var namespace = ""
    @State private var result: FlowHistory?
    @State private var error: String?
    @State private var loading = false
    @State private var sortOrder = [KeyPathComparator(\FlowHistoryRecord.observedAt, order: .reverse)]

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("Since", selection: $since) { ForEach(["15m", "1h", "6h", "24h", "168h"], id: \.self) { Text($0).tag($0) } }.frame(width: 140)
                TextField("Namespace", text: $namespace).textFieldStyle(.roundedBorder).frame(width: 180)
                Button { Task { await load() } } label: { Label("Reload", systemImage: "arrow.clockwise") }
                if loading { ProgressView().controlSize(.small) }
                Spacer()
                if let r = result { Text("\(r.records.count) of \(r.matched)\(r.truncated ? " (truncated)" : "")").font(.caption).foregroundStyle(.secondary) }
            }.padding(8)
            Divider()
            if let error { ContentUnavailableView("History unavailable", systemImage: "exclamationmark.triangle", description: Text(error)) }
            else {
                Table((result?.records ?? []).sorted(using: sortOrder), sortOrder: $sortOrder) {
                    TableColumn("Observed", value: \.observedAt) { Text($0.observedAt).font(.caption.monospaced()) }
                    TableColumn("Workload", value: \.pod) { Text([$0.namespace, $0.pod].filter { !$0.isEmpty }.joined(separator: "/")) }
                    TableColumn("Peer", value: \.peer) { Text("\($0.peer):\($0.port)").font(.caption.monospaced()) }
                    TableColumn("Proto", value: \.proto) { Text($0.proto + ($0.appProtocol.isEmpty ? "" : "/\($0.appProtocol)")) }
                    TableColumn("Dir", value: \.direction) { Text($0.direction) }
                    TableColumn("Packets", value: \.packets) { Text("\($0.packets)").monospacedDigit() }
                    TableColumn("Bytes", value: \.bytes) { Text(ByteCountFormatter.string(fromByteCount: Int64($0.bytes), countStyle: .binary)).monospacedDigit() }
                    TableColumn("Blocked", value: \.blocked) { Text("\($0.blocked)").monospacedDigit() }
                    TableColumn("Comm", value: \.comm) { Text($0.comm) }
                    TableColumn("SNI/DNS") { Text($0.tlsSni.isEmpty ? $0.dnsName : $0.tlsSni) }
                }
            }
        }
        .task(id: model.baseURLText) { await load() }
    }

    private func load() async {
        guard let c = model.client else { error = "No connection"; return }
        loading = true; defer { loading = false }
        do { result = try await c.flowHistory(since: since, limit: 500, namespace: namespace); error = nil }
        catch { self.error = String(describing: error) }
    }
}

struct FlowsSummaryView: View {
    @Environment(AppModel.self) private var model
    @State private var summary: FlowsSummary?
    @State private var error: String?
    @State private var loading = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Button { Task { await load() } } label: { Label("Reload", systemImage: "arrow.clockwise") }
                    if loading { ProgressView().controlSize(.small) }
                    Text("Sample of recent flows (about 8 s window)").font(.caption).foregroundStyle(.secondary)
                }
                if let error { Text(error).foregroundStyle(.red) }
                if let s = summary {
                    Text("\(s.total) flows sampled").font(.title3.bold())
                    countGrid("Verdicts", s.verdicts)
                    countGrid("Protocols", s.protocols)
                    list("Drop reasons", s.dropReasons)
                    list("Top destinations", s.topDestinations)
                    list("Top workloads", s.topWorkloads)
                    list("Top blocked workloads", s.topBlockedWorkloads)
                }
            }.padding()
        }
        .task(id: model.baseURLText) { await load() }
    }

    @ViewBuilder private func countGrid(_ title: String, _ m: [String: Int]) -> some View {
        if !m.isEmpty {
            VStack(alignment: .leading) {
                Text(title).font(.headline)
                ForEach(m.sorted { $0.value > $1.value }, id: \.key) { k, v in
                    HStack { Text(k); Spacer(); Text("\(v)").monospacedDigit() }.frame(maxWidth: 360)
                }
            }
        }
    }
    @ViewBuilder private func list(_ title: String, _ items: [FlowNamedCount]) -> some View {
        if !items.isEmpty {
            VStack(alignment: .leading) {
                Text(title).font(.headline)
                ForEach(items) { i in HStack { Text(i.name).lineLimit(1); Spacer(); Text("\(i.count)").monospacedDigit() }.frame(maxWidth: 480) }
            }
        }
    }
    private func load() async {
        guard let c = model.client else { error = "No connection"; return }
        loading = true; defer { loading = false }
        do { summary = try await c.flowSummary(); error = nil } catch { self.error = String(describing: error) }
    }
}
