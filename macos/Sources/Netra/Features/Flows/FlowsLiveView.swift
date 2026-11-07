// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import AppKit
import NetraKit

struct FlowsLiveView: View {
    @Environment(AppModel.self) private var model
    @State private var flows = FlowsModel()
    @State private var query = ""
    @State private var selection: FlowRecord.ID?
    @State private var sortOrder = [KeyPathComparator(\FlowRecord.id, order: .reverse)]
    @FocusState private var searchFocused: Bool

    private var visible: [FlowRecord] {
        let q = query.lowercased().trimmingCharacters(in: .whitespaces)
        let base = q.isEmpty ? flows.rows : flows.rows.filter { $0.searchText.contains(q) }
        return base.sorted(using: sortOrder)
    }
    private var selected: FlowRecord? { selection.flatMap { id in flows.rows.first { $0.id == id } } }

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            HSplitView {
                Table(visible, selection: $selection, sortOrder: $sortOrder) {
                    TableColumn("Time", value: \.time) { Text(shortTime($0)).monospacedDigit() }.width(min: 70, ideal: 90)
                    TableColumn("Verdict", value: \.verdict) { Text($0.verdict).foregroundStyle(verdictColor($0.verdict)) }.width(min: 70, ideal: 90)
                    TableColumn("Dir", value: \.direction) { Text($0.direction) }.width(min: 55, ideal: 70)
                    TableColumn("Source", value: \.source) { Text($0.source).lineLimit(1) }
                    TableColumn("Destination", value: \.destination) { Text($0.destination).lineLimit(1) }
                    TableColumn("Tuple", value: \.sourceEndpoint) { Text("\($0.sourceEndpoint) → \($0.destinationEndpoint)").font(.caption.monospaced()).lineLimit(1) }
                    TableColumn("Proto", value: \.proto) { Text($0.proto) }.width(min: 50, ideal: 60)
                }
                .contextMenu(forSelectionType: FlowRecord.ID.self) { ids in
                    Button("Copy row as JSON") { copy(ids) }
                }
                .frame(minWidth: 480)
                if let f = selected { FlowInspector(flow: f).frame(minWidth: 280, idealWidth: 340) }
            }
            statusBar
        }
        .task(id: reconnectKey) { flows.start(client: model.client) }
        .onDisappear { flows.stop() }
    }

    private var reconnectKey: String { model.baseURLText + "|" + "\(flows.filter.hashValueKey)" }

    private var toolbar: some View {
        HStack(spacing: 10) {
            Button { flows.paused.toggle() } label: {
                Label(flows.paused ? "Resume" : "Pause", systemImage: flows.paused ? "play.fill" : "pause.fill")
            }
            Button { flows.clear() } label: { Label("Clear", systemImage: "trash") }
            Picker("Verdict", selection: Bindable(flows).filter.verdict) {
                Text("Any verdict").tag("")
                ForEach(["FORWARDED", "DROPPED", "ERROR", "AUDIT"], id: \.self) { Text($0.capitalized).tag($0) }
            }.frame(width: 140)
            Picker("Direction", selection: Bindable(flows).filter.direction) {
                Text("Any direction").tag("")
                Text("Egress").tag("EGRESS"); Text("Ingress").tag("INGRESS")
            }.frame(width: 140)
            TextField("Filter (⌘F)", text: $query).textFieldStyle(.roundedBorder).focused($searchFocused).frame(maxWidth: 260)
            Button("") { searchFocused = true }.keyboardShortcut("f", modifiers: .command).opacity(0).frame(width: 0)
            Spacer()
            Button { if let f = selected { copyOne(f) } } label: { Label("Copy JSON", systemImage: "doc.on.doc") }
                .disabled(selected == nil)
        }.padding(8).labelStyle(.titleAndIcon)
    }

    private var statusBar: some View {
        HStack {
            Circle().fill(stateColor).frame(width: 8, height: 8)
            Text(stateText)
            Spacer()
            Text(String(format: "%.1f rows/s", flows.rate)).monospacedDigit()
            Text("\(visible.count) shown · \(flows.rows.count)/\(FlowsModel.capacity) buffered · \(flows.total) total").monospacedDigit()
            if flows.paused { Text("PAUSED").bold().foregroundStyle(.orange) }
        }.font(.caption).padding(.horizontal, 10).padding(.vertical, 5)
    }

    private var stateColor: Color {
        switch flows.state { case .live: .green; case .connecting: .yellow; case .reconnecting: .orange; case .failed: .red }
    }
    private var stateText: String {
        switch flows.state {
        case .live: "Live"
        case .connecting: "Connecting…"
        case .reconnecting(let n, let d, let r): "Reconnecting (#\(n), \(Int(d))s): \(r)"
        case .failed(let m): "Stream failed: \(m)"
        }
    }

    private func shortTime(_ f: FlowRecord) -> String {
        guard let d = f.timestamp else { return f.time }
        return d.formatted(.dateTime.hour().minute().second())
    }
    private func copy(_ ids: Set<FlowRecord.ID>) {
        let rows = flows.rows.filter { ids.contains($0.id) }
        guard !rows.isEmpty else { return }
        write(rows.map(\.prettyJSON).joined(separator: "\n"))
    }
    private func copyOne(_ f: FlowRecord) { write(f.prettyJSON) }
    private func write(_ s: String) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(s, forType: .string) }
}

func verdictColor(_ v: String) -> Color {
    switch v.uppercased() { case "FORWARDED": .green; case "DROPPED": .red; case "AUDIT", "ERROR": .orange; default: .secondary }
}

extension FlowFilterParams {
    var hashValueKey: String { queryItems.map { "\($0.name)=\($0.value ?? "")" }.joined(separator: "&") }
}

struct FlowInspector: View {
    let flow: FlowRecord
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                Text("Flow").font(.headline)
                row("Verdict", flow.verdict); row("Direction", flow.direction)
                row("Source", flow.source); row("Destination", flow.destination)
                row("Source addr", flow.sourceEndpoint); row("Destination addr", flow.destinationEndpoint)
                row("Protocol", flow.proto); row("Time", flow.time)
                if !flow.dropReason.isEmpty { row("Drop reason", flow.dropReason) }
                Divider()
                Text("Raw").font(.subheadline.bold())
                Text(flow.prettyJSON).font(.caption.monospaced()).textSelection(.enabled)
            }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    @ViewBuilder private func row(_ k: String, _ v: String) -> some View {
        if !v.isEmpty { HStack(alignment: .top) { Text(k).foregroundStyle(.secondary).frame(width: 110, alignment: .leading); Text(v).textSelection(.enabled) } }
    }
}
