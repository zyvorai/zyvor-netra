// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

struct AnomaliesPage: View {
    @Environment(AppModel.self) private var model
    @State private var list = Poller<AnomalySummary>()
    @State private var evidence = Poller<MetricEvidence>()
    @State private var range: MetricRange = .m15
    @State private var pick: MetricRanked.ID?

    private var ranked: [MetricRanked] { (list.value?.ranked ?? []).filter { $0.anomalyRate > 0 } }
    private var current: MetricRanked? { ranked.first { $0.id == pick } }

    var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Anomalous metrics").font(.title3.weight(.semibold))
                    Spacer(); RangePicker(range: $range)
                }
                Text("Rate is the percent of samples flagged by the on-node models. Read-only.").font(.caption).foregroundStyle(.secondary)
                if let e = list.error { ErrorBanner(text: e) }
                if let nodes = list.value?.nodes, !nodes.isEmpty {
                    ScrollView(.horizontal) { HStack { ForEach(nodes) { n in
                        StatusBadge(text: "\(n.node) \(String(format: "%.1f", n.anomalyRate))%", tint: .secondary)
                    } } }
                }
                List(ranked, selection: $pick) { r in
                    HStack {
                        StatusBadge(text: r.severity.label, tint: r.severity.tint)
                        VStack(alignment: .leading, spacing: 1) {
                            Text("\(r.chart) / \(r.dimension)").lineLimit(1)
                            Text("\(r.node) · \(r.context)").font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                        }
                        Spacer()
                        Text(String(format: "%.1f%%", r.anomalyRate)).font(.callout.monospacedDigit())
                    }.tag(r.id)
                }
                .overlay {
                    if list.value != nil && ranked.isEmpty && list.error == nil {
                        ContentUnavailableView("No anomalies", systemImage: "checkmark.circle", description: Text("Nothing flagged in the last \(range.rawValue)."))
                    }
                }
            }
            .padding(16).frame(minWidth: 420)
            evidencePane.frame(minWidth: 320, idealWidth: 380)
        }
        .navigationTitle("Anomalies")
        .task(id: range) { await loop() }
        .task(id: pick) { await loadEvidence() }
    }

    @ViewBuilder private var evidencePane: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Evidence").font(.title3.weight(.semibold))
            if let r = current {
                Text("\(r.chart) / \(r.dimension) on \(r.node)").font(.callout)
                if let e = evidence.error { ErrorBanner(text: e) }
                if let ev = evidence.value {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("\(ev.flowRecords) flow records in window").font(.caption).foregroundStyle(.secondary)
                            if !ev.topPeers.isEmpty {
                                Text("Top peers").font(.headline)
                                ForEach(Array(ev.topPeers.enumerated()), id: \.offset) { _, p in
                                    Text("\(p.peer):\(p.port) \(p.protocolName ?? "") · \(p.bytes) B" + ((p.retransmissions ?? 0) > 0 ? " · \(p.retransmissions!) retrans" : "") + ((p.blocked ?? 0) > 0 ? " · \(p.blocked!) blocked" : ""))
                                        .font(.caption.monospacedDigit())
                                }
                            }
                            if !ev.kernelDrops.isEmpty {
                                Text("Kernel drops").font(.headline)
                                ForEach(ev.kernelDrops, id: \.name) { Text("\($0.name): \($0.count)").font(.caption.monospacedDigit()) }
                            }
                            if !ev.links.isEmpty {
                                Text("Related").font(.headline)
                                ForEach(Array(ev.links.enumerated()), id: \.offset) { _, l in
                                    VStack(alignment: .leading, spacing: 0) {
                                        Text(l.title).font(.callout); Text(l.why).font(.caption2).foregroundStyle(.secondary)
                                    }
                                }
                            }
                            ForEach(ev.limitations, id: \.self) { Text($0).font(.caption2).foregroundStyle(.secondary) }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                } else if evidence.error == nil { ProgressView() }
            } else {
                ContentUnavailableView("Select an anomaly", systemImage: "waveform.badge.exclamationmark", description: Text("Evidence shows flow peers, drops and related links."))
            }
            Spacer(minLength: 0)
        }.padding(16)
    }

    private func loop() async {
        let secs = range.seconds
        while !Task.isCancelled {
            guard let c = model.client else { return }
            await list.refresh { try await c.metricsAnomalies(seconds: secs) }
            try? await Task.sleep(for: .seconds(5))
        }
    }

    private func loadEvidence() async {
        evidence.value = nil; evidence.error = nil
        guard let r = current, let c = model.client else { return }
        let secs = range.seconds
        await evidence.refresh { try await c.metricsEvidence(context: r.context, node: r.node, seconds: secs) }
    }
}
