// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// "What changed": snapshots a few observe endpoints while the page is open and diffs the newest against an
/// earlier one chosen on the timeline. Read-only; nothing here mutates the controller.
struct ChangesPage: View {
    @Environment(AppModel.self) private var model
    @State private var store = ChangesModel.shared
    @State private var baselineIndex: Double = 0
    @State private var followPrevious = true
    @State private var interval = 30.0
    @State private var live = true

    private var snaps: [ChangeSnapshot] { store.history.snapshots }
    private var order: [String] { SnapshotSource.standard.map(\.key) }
    private var titles: [String: String] { Dictionary(uniqueKeysWithValues: SnapshotSource.standard.map { ($0.key, $0.title) }) }
    private var baselineID: String? {
        guard snaps.count >= 2 else { return nil }
        if followPrevious { return snaps[snaps.count - 2].id }
        return snaps[min(max(Int(baselineIndex), 0), snaps.count - 2)].id
    }
    private var diff: SnapshotDiff? { store.history.diffToLatest(baselineID: baselineID, order: order) }

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else {
                VStack(spacing: 0) {
                    timeline.padding()
                    Divider()
                    content
                }
            }
        }
        .navigationTitle("What changed")
        .navigationSubtitle("Read-only snapshots, compared in this app")
        .toolbar {
            Toggle("Auto", systemImage: "dot.radiowaves.left.and.right", isOn: $live)
            Picker("Every", selection: $interval) {
                Text("10 s").tag(10.0); Text("30 s").tag(30.0); Text("1 min").tag(60.0); Text("5 min").tag(300.0)
            }
            Button("Snapshot now", systemImage: "camera") { Task { await snapshot() } }.disabled(store.busy)
            Button("Clear", systemImage: "trash") { store.clear() }.disabled(snaps.isEmpty)
        }
        .task(id: model.activeProfileID) { store.bind(profileID: model.activeProfileID); await snapshot() }
        .task(id: "\(live)-\(interval)-\(model.activeProfileID ?? "")") {
            guard live else { return }
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(interval))
                if Task.isCancelled { break }
                await snapshot()
            }
        }
    }

    private func snapshot() async {
        guard let c = model.client, model.whoami != nil else { return }
        await store.capture(using: c)
    }

    // MARK: Timeline

    @ViewBuilder private var timeline: some View {
        VStack(alignment: .leading, spacing: 8) {
            if snaps.count < 2 {
                Label("Collected \(snaps.count) of 2 snapshots needed. Keep this page open; a snapshot is taken every \(Int(interval)) s.",
                      systemImage: "clock").foregroundStyle(.secondary)
            } else {
                HStack {
                    Text("Compare now against").font(.headline)
                    Spacer()
                    Toggle("Previous snapshot", isOn: $followPrevious).toggleStyle(.checkbox)
                }
                let maxIdx = Double(snaps.count - 2)
                Slider(value: $baselineIndex, in: 0...max(maxIdx, 1), step: 1) { Text("Baseline snapshot") }
                    .disabled(followPrevious || snaps.count < 3)
                    .accessibilityValue(baselineID.flatMap { id in snaps.first { $0.id == id }?.takenAt.formatted(date: .abbreviated, time: .standard) } ?? "")
                if let d = diff {
                    HStack(spacing: 14) {
                        Text("\(d.from.formatted(date: .omitted, time: .standard))  to  \(d.to.formatted(date: .omitted, time: .standard))")
                            .monospacedDigit()
                        Label("\(d.count(.added)) added", systemImage: "plus.circle").foregroundStyle(.green)
                        Label("\(d.count(.changed)) changed", systemImage: "pencil.circle").foregroundStyle(.orange)
                        Label("\(d.count(.removed)) removed", systemImage: "minus.circle").foregroundStyle(.red)
                        Spacer()
                        Text("\(snaps.count) snapshots held (max \(ChangesModel.capacity))").font(.caption).foregroundStyle(.secondary)
                    }.font(.callout)
                }
            }
            if !store.failures.isEmpty {
                Label("Not captured this round: " + store.failures.keys.sorted().compactMap { titles[$0] }.joined(separator: ", ")
                      + ". Those sources are skipped rather than shown as removed.", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
    }

    // MARK: Diff

    @ViewBuilder private var content: some View {
        if let d = diff {
            if d.isEmpty {
                ContentUnavailableView("No changes", systemImage: "checkmark.circle", description: Text("Nothing differs between the two snapshots."))
            } else {
                List {
                    ForEach(d.sources.filter { !$0.isEmpty }) { sd in
                        Section("\(titles[sd.key] ?? sd.key)  ·  \(sd.changes.count)") {
                            ForEach(sd.changes) { ch in ChangeRow(change: ch) }
                        }
                    }
                    let skipped = d.sources.filter(\.incomparable).compactMap { titles[$0.key] }
                    if !skipped.isEmpty {
                        Section { Text("Not comparable (missing in one snapshot): " + skipped.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary) }
                    }
                }
            }
        } else {
            ContentUnavailableView("Waiting for snapshots", systemImage: "camera.metering.none")
        }
    }
}

private struct ChangeRow: View {
    let change: ItemChange
    private var symbol: (name: String, tint: Color, word: String) {
        switch change.kind {
        case .added: ("plus.circle.fill", .green, "Added")
        case .removed: ("minus.circle.fill", .red, "Removed")
        case .changed: ("pencil.circle.fill", .orange, "Changed")
        }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Label(change.label, systemImage: symbol.name).foregroundStyle(symbol.tint)
                Text(symbol.word).font(.caption).foregroundStyle(.secondary)
                if change.label != change.id { Text(change.id).font(.caption.monospaced()).foregroundStyle(.tertiary) }
            }
            ForEach(change.fields, id: \.field) { f in
                HStack(spacing: 6) {
                    Text(f.field).font(.caption.monospaced()).foregroundStyle(.secondary)
                    Text(f.old ?? "(absent)").font(.caption.monospaced()).strikethrough().foregroundStyle(.red)
                    Image(systemName: "arrow.right").font(.caption2).foregroundStyle(.secondary)
                    Text(f.new ?? "(absent)").font(.caption.monospaced()).foregroundStyle(.green)
                }.padding(.leading, 22).textSelection(.enabled)
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}
