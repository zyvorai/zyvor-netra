// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// Metric contexts browser with node and fleet tabs. Read-only.
struct MxContextsPage: View {
    enum Tab: String, CaseIterable, Identifiable { case contexts = "Contexts", nodes = "Nodes", fleet = "Fleet"; var id: String { rawValue } }
    @State private var tab: Tab = .contexts

    var body: some View {
        VStack(spacing: 0) {
            Picker("View", selection: $tab) { ForEach(Tab.allCases) { Text($0.rawValue).tag($0) } }
                .pickerStyle(.segmented).labelsHidden().frame(width: 280).padding(10)
            switch tab {
            case .contexts: MxContextsTab()
            case .nodes: MxNodesTab()
            case .fleet: MxFleetTab()
            }
        }
        .navigationTitle("Metric contexts")
    }
}

private struct MxContextsTab: View {
    @Environment(AppModel.self) private var model
    @State private var contexts = Poller<[MetricContext]>()
    @State private var nodes = Poller<[MetricNodeInfo]>()
    @State private var data = Poller<MetricResult>()
    @State private var selected: String?
    @State private var range: MetricRange = .m15
    @State private var node = ""
    @State private var search = ""

    private var groups: [(family: String, contexts: [MetricContext])] {
        let q = search.lowercased()
        let f = (contexts.value ?? []).filter { q.isEmpty || $0.context.lowercased().contains(q) || ($0.title ?? "").lowercased().contains(q) }
        return MetricsMore.groupByFamily(f)
    }
    private var current: MetricContext? { contexts.value?.first { $0.context == selected } }

    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                TextField("Filter contexts", text: $search).textFieldStyle(.roundedBorder).padding(8)
                if let e = contexts.error { ErrorBanner(text: e).padding(8) }
                List(selection: $selected) {
                    ForEach(groups, id: \.family) { g in
                        Section(g.family) {
                            ForEach(g.contexts) { c in
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(c.title ?? c.context).lineLimit(1)
                                    Text("\(c.context) · \(c.charts.count) chart(s)").font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                                }.tag(c.context)
                            }
                        }
                    }
                }
                .overlay { if contexts.value?.isEmpty == true { ContentUnavailableView("No contexts", systemImage: "list.bullet.rectangle") } }
            }.frame(minWidth: 240, idealWidth: 290, maxWidth: 380)
            detail.frame(minWidth: 440)
        }
        .task { await slowLoop() }
        .task(id: "\(selected ?? "")|\(range.rawValue)|\(node)") { await fastLoop() }
    }

    @ViewBuilder private var detail: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(current?.title ?? selected ?? "Select a context").font(.title3.weight(.semibold)).lineLimit(1)
                Spacer()
                Picker("Node", selection: $node) {
                    Text("All nodes").tag("")
                    ForEach(nodes.value ?? []) { Text($0.node).tag($0.node) }
                }.frame(width: 160)
                RangePicker(range: $range)
            }
            if let c = current {
                Text([c.family, c.units.map { "units: \($0)" }, c.chartType, "\(c.charts.count) chart(s)"].compactMap { $0 }.joined(separator: " · "))
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let e = data.error { ErrorBanner(text: e) }
            if selected == nil {
                ContentUnavailableView("Pick a context", systemImage: "list.bullet.rectangle", description: Text("Charts for the selection load from /metrics/data."))
            } else if let r = data.value {
                if r.dimensions.isEmpty || r.timestamps.isEmpty { ContentUnavailableView("No data in this range", systemImage: "chart.line.flattrend.xyaxis") }
                else { MxMiniChart(result: r) }
            } else if data.error == nil { ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity) }
            if let c = current, !c.charts.isEmpty {
                Text("Charts").font(.headline)
                List(c.charts.prefix(40).indices, id: \.self) { i in
                    let ch = c.charts[i]
                    VStack(alignment: .leading, spacing: 1) {
                        Text("\(ch.node) · \(ch.chart)").font(.callout)
                        Text(([MetricsMore.labelsParam(ch.labels ?? [:])].compactMap { $0 } + [ch.dimensions.joined(separator: ", ")]).joined(separator: " · "))
                            .font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                    }
                }.frame(maxHeight: 160)
            }
            Spacer(minLength: 0)
        }.padding(16)
    }

    private func slowLoop() async {
        while !Task.isCancelled {
            guard let c = model.client else { return }
            await contexts.refresh { try await c.metricsContexts() }
            await nodes.refresh { try await c.metricsNodes() }
            if selected == nil, let f = contexts.value?.first { selected = f.context }
            try? await Task.sleep(for: .seconds(10))
        }
    }
    private func fastLoop() async {
        guard let ctx = selected else { return }
        let secs = range.seconds, n = node
        while !Task.isCancelled {
            guard let c = model.client else { return }
            await data.refresh { try await c.metricsData(context: ctx, seconds: secs, nodes: n.isEmpty ? [] : [n]) }
            try? await Task.sleep(for: .seconds(5))
        }
    }
}

/// Multi-line chart of every dimension in a result.
struct MxMiniChart: View {
    let result: MetricResult
    private struct Pt: Identifiable { let id: String; let dim: String; let t: Date; let v: Double }
    private var points: [Pt] {
        var out: [Pt] = []
        for d in result.dimensions.prefix(12) {
            for (i, t) in result.timestamps.enumerated() where i < d.values.count {
                if let v = d.values[i] { out.append(Pt(id: "\(d.name)|\(t)", dim: d.name, t: Date(timeIntervalSince1970: Double(t)), v: v)) }
            }
        }
        return out
    }
    var body: some View {
        Chart(points) { p in
            LineMark(x: .value("Time", p.t), y: .value("Value", p.v), series: .value("Dimension", p.dim))
                .foregroundStyle(by: .value("Dimension", p.dim))
        }
        .chartYAxis { AxisMarks { v in AxisGridLine(); AxisValueLabel { if let d = v.as(Double.self) { Text(MetricsFormat.value(d, units: nil)) } } } }
        .frame(minHeight: 240, maxHeight: 340)
        .accessibilityLabel("\(result.title ?? result.context), \(result.dimensions.count) dimensions, \(result.matched) series")
    }
}

private struct MxNodesTab: View {
    @Environment(AppModel.self) private var model
    @State private var nodes = Poller<[MetricNodeInfo]>()
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let e = nodes.error { ErrorBanner(text: e) }
            Table(nodes.value ?? []) {
                TableColumn("Node") { Text($0.node) }
                TableColumn("Last ingest") { n in
                    HStack { Text(relative(n.lastIngest)); if MetricsMore.isStale(n) { StatusBadge(text: "Stale", tint: .orange) } }
                }
                TableColumn("Series") { Text("\($0.stats?.series ?? 0)").monospacedDigit() }
                TableColumn("Memory") { Text(MetricsMore.bytes($0.stats?.memoryBytes)) }
                TableColumn("Disk") { Text(MetricsMore.bytes($0.stats?.diskBytes)) }
            }
            .overlay { if nodes.value?.isEmpty == true { ContentUnavailableView("No nodes streaming", systemImage: "server.rack") } }
        }
        .padding(.horizontal, 16).padding(.bottom, 12)
        .task { while !Task.isCancelled { guard let c = model.client else { return }; await nodes.refresh { try await c.metricsNodes() }; try? await Task.sleep(for: .seconds(5)) } }
    }
}

private struct MxFleetTab: View {
    @Environment(AppModel.self) private var model
    @State private var fleet = Poller<MetricsFleet>()
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if let e = fleet.error { ErrorBanner(text: e) }
                if let f = fleet.value {
                    if let t = f.totals {
                        HStack(spacing: 18) {
                            stat("Clusters", "\(t.okClusters)/\(t.clusters) reachable"); stat("Nodes", "\(t.nodes)"); stat("Series", "\(t.series)")
                            stat("Anomaly rate", String(format: "%.1f%%", t.anomalyRate)); stat("Alerts", "\(t.alertsCritical) crit / \(t.alertsWarning) warn")
                        }
                    }
                    ForEach(f.clusters) { c in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text(c.name).font(.headline)
                                if c.local == true { StatusBadge(text: "This cluster", tint: .secondary) }
                                StatusBadge(text: c.ok ? "OK" : "Unreachable", tint: c.ok ? .green : .orange)
                                if let t = c.tenant, !t.isEmpty { Text(t).font(.caption).foregroundStyle(.secondary) }
                            }
                            if let e = c.error, !e.isEmpty { Text(e).font(.caption).foregroundStyle(.orange) }
                            if let s = c.summary, s.available {
                                Text("\(s.nodes) nodes (\(s.staleNodes) stale) · \(s.series) series · anomaly \(String(format: "%.1f", s.anomalyRate))% · \(s.alertsCritical) crit / \(s.alertsWarning) warn")
                                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            }
                        }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
                         .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
                    }
                    if let n = f.note { Text(n).font(.caption2).foregroundStyle(.secondary) }
                } else if fleet.error == nil { ProgressView().frame(maxWidth: .infinity) }
            }.padding(16)
        }
        .task { while !Task.isCancelled { guard let c = model.client else { return }; await fleet.refresh { try await c.metricsFleet() }; try? await Task.sleep(for: .seconds(15)) } }
    }
    private func stat(_ k: String, _ v: String) -> some View {
        VStack(alignment: .leading, spacing: 0) { Text(k).font(.caption2).foregroundStyle(.secondary); Text(v).font(.callout.monospacedDigit().weight(.medium)) }
    }
}
