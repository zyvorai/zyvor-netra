// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

struct MetricsChartPage: View {
    @Environment(AppModel.self) private var model
    @State private var contexts = Poller<[MetricContext]>()
    @State private var data = Poller<MetricResult>()
    @State private var summary = Poller<MetricsSummary>()
    @State private var nodes = Poller<[MetricNodeInfo]>()
    @State private var selected: String?
    @State private var range: MetricRange = .m15
    @State private var node = ""
    @State private var focus: String?
    @State private var hover: Date?
    @State private var search = ""

    private var filtered: [MetricContext] {
        let q = search.lowercased()
        return (contexts.value ?? []).filter { q.isEmpty || $0.context.lowercased().contains(q) || ($0.title ?? "").lowercased().contains(q) }
    }

    var body: some View {
        HSplitView {
            picker.frame(minWidth: 220, idealWidth: 260, maxWidth: 360)
            detail.frame(minWidth: 460)
        }
        .navigationTitle("Metrics")
        .task { await slowLoop() }
        .task(id: "\(selected ?? "")|\(range.rawValue)|\(node)") { await fastLoop() }
    }

    private var picker: some View {
        VStack(spacing: 0) {
            TextField("Filter metrics", text: $search).textFieldStyle(.roundedBorder).padding(8)
            if let e = contexts.error { ErrorBanner(text: e).padding(8) }
            List(filtered, selection: $selected) { c in
                VStack(alignment: .leading, spacing: 1) {
                    Text(c.title ?? c.context).lineLimit(1)
                    Text(c.context).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                }.tag(c.context)
            }
            .overlay { if contexts.value?.isEmpty == true { ContentUnavailableView("No metrics", systemImage: "chart.xyaxis.line", description: Text("No contexts reported yet.")) } }
        }
    }

    private var detail: some View {
        VStack(alignment: .leading, spacing: 12) {
            summaryRow
            HStack {
                Text(data.value?.title ?? selected ?? "Select a metric").font(.title3.weight(.semibold)).lineLimit(1)
                Spacer()
                Picker("Node", selection: $node) {
                    Text("All nodes").tag("")
                    ForEach(nodes.value ?? []) { Text($0.node).tag($0.node) }
                }.frame(width: 160)
                RangePicker(range: $range)
            }
            if let e = data.error { ErrorBanner(text: e) }
            if selected == nil {
                ContentUnavailableView("Pick a metric", systemImage: "chart.xyaxis.line", description: Text("Choose a context on the left."))
            } else if let r = data.value {
                if r.dimensions.isEmpty || r.timestamps.isEmpty {
                    ContentUnavailableView("No data in this range", systemImage: "chart.line.flattrend.xyaxis")
                } else { chart(r); legend(r) }
            } else if data.error == nil { ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity) }
            Spacer(minLength: 0)
        }
        .padding(16)
    }

    private var summaryRow: some View {
        HStack(spacing: 18) {
            if let s = summary.value, s.available {
                stat("Nodes", "\(s.nodes)" + (s.staleNodes > 0 ? " (\(s.staleNodes) stale)" : ""))
                stat("Series", "\(s.series)")
                stat("Anomaly rate", String(format: "%.1f%%", s.anomalyRate))
                stat("Alerts", "\(s.alertsCritical) crit / \(s.alertsWarning) warn")
            } else if let e = summary.error { Text(e).font(.caption).foregroundStyle(.secondary) }
            Spacer()
            Text("Refreshes every 5s").font(.caption2).foregroundStyle(.secondary)
        }
    }
    private func stat(_ k: String, _ v: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(k).font(.caption2).foregroundStyle(.secondary)
            Text(v).font(.callout.monospacedDigit().weight(.medium))
        }
    }

    private struct Pt: Identifiable { let id: String; let dim: String; let t: Date; let v: Double }

    private func points(_ r: MetricResult) -> [Pt] {
        var out: [Pt] = []
        for d in r.dimensions {
            for (i, t) in r.timestamps.enumerated() where i < d.values.count {
                if let v = d.values[i] { out.append(Pt(id: "\(d.name)|\(t)", dim: d.name, t: Date(timeIntervalSince1970: Double(t)), v: v)) }
            }
        }
        return out
    }

    private func focusName(_ r: MetricResult) -> String { focus.flatMap { f in r.dimensions.contains { $0.name == f } ? f : nil } ?? r.dimensions[0].name }

    @ViewBuilder private func chart(_ r: MetricResult) -> some View {
        let pts = points(r)
        let fn = focusName(r)
        Chart {
            ForEach(pts.filter { $0.dim != fn }) { p in
                LineMark(x: .value("Time", p.t), y: .value("Value", p.v), series: .value("Dim", p.dim))
                    .foregroundStyle(Color.secondary.opacity(0.4)).lineStyle(StrokeStyle(lineWidth: 1))
            }
            ForEach(pts.filter { $0.dim == fn }) { p in
                AreaMark(x: .value("Time", p.t), y: .value("Value", p.v)).foregroundStyle(Color.accentColor.opacity(0.15))
                LineMark(x: .value("Time", p.t), y: .value("Value", p.v)).foregroundStyle(Color.accentColor).lineStyle(StrokeStyle(lineWidth: 2))
            }
            if let h = hover, let i = MetricsFormat.nearestIndex(r.timestamps, to: h.timeIntervalSince1970) {
                RuleMark(x: .value("Time", Date(timeIntervalSince1970: Double(r.timestamps[i]))))
                    .foregroundStyle(Color.secondary).lineStyle(StrokeStyle(lineWidth: 1, dash: [3]))
                    .annotation(position: .top, spacing: 4, overflowResolution: .init(x: .fit(to: .chart), y: .disabled)) { readout(r, i) }
            }
        }
        .chartYAxis { AxisMarks { v in AxisGridLine(); AxisValueLabel { if let d = v.as(Double.self) { Text(MetricsFormat.value(d, units: nil)) } } } }
        .chartOverlay { proxy in
            GeometryReader { geo in
                Rectangle().fill(.clear).contentShape(Rectangle())
                    .onContinuousHover { phase in
                        switch phase {
                        case .active(let loc):
                            if let frame = proxy.plotFrame { hover = proxy.value(atX: loc.x - geo[frame].origin.x, as: Date.self) }
                        case .ended: hover = nil
                        }
                    }
            }
        }
        .frame(minHeight: 260, maxHeight: 380)
        .accessibilityLabel("\(r.title ?? r.context) over \(range.rawValue)")
        .accessibilityValue(summaryText(r, fn))
    }

    private func summaryText(_ r: MetricResult, _ fn: String) -> String {
        guard let d = r.dimensions.first(where: { $0.name == fn }), let last = d.values.last(where: { $0 != nil }) ?? nil else { return "no data" }
        return "\(fn) latest \(MetricsFormat.value(last, units: r.units))"
    }

    private func readout(_ r: MetricResult, _ i: Int) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(Date(timeIntervalSince1970: Double(r.timestamps[i])).formatted(date: .omitted, time: .standard)).font(.caption2).foregroundStyle(.secondary)
            ForEach(r.dimensions.prefix(6)) { d in
                if i < d.values.count, let v = d.values[i] {
                    Text("\(d.name): \(MetricsFormat.value(v, units: r.units))").font(.caption.monospacedDigit())
                }
            }
        }
        .padding(6).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 6))
    }

    private func legend(_ r: MetricResult) -> some View {
        let fn = focusName(r)
        return ScrollView(.horizontal) {
            HStack {
                ForEach(r.dimensions) { d in
                    Button { focus = d.name } label: {
                        HStack(spacing: 4) {
                            Circle().fill(d.name == fn ? Color.accentColor : Color.secondary.opacity(0.5)).frame(width: 8, height: 8)
                            Text(d.name).font(.caption)
                        }
                    }.buttonStyle(.plain)
                }
                Text("tier \(r.tier) · \(r.interval)s · \(r.matched) series").font(.caption2).foregroundStyle(.secondary)
            }
        }
    }

    // MARK: loading

    private func slowLoop() async {
        while !Task.isCancelled {
            guard let c = model.client else { return }
            await summary.refresh { try await c.metricsSummary() }
            await nodes.refresh { try await c.metricsNodes() }
            await contexts.refresh { try await c.metricsContexts() }
            if selected == nil, let f = contexts.value?.first { selected = f.context }
            try? await Task.sleep(for: .seconds(5))
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
