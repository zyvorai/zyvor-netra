// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Behaviour and rate baseline age. Read-only: capturing or clearing a baseline is a separate, mutating action.
struct PlatBaselinesPage: View {
    @State private var query = ""
    var body: some View {
        JSONLoader(title: "Baselines", path: "api/v1/baselines") { json in
            let b = PlatformData.baselines(json)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 10) {
                        StatCard(title: "Status", value: b.stale ? "Stale" : (b.behavior.present || b.rate.present ? "Fresh" : "None"),
                                 symbol: b.stale ? "exclamationmark.triangle" : "checkmark.seal", tint: b.stale ? .orange : .green)
                        StatCard(title: "Behavior entries", value: "\(b.behavior.entries)", symbol: "list.number")
                        StatCard(title: "Rate entries", value: "\(b.rate.entries)", symbol: "speedometer")
                        Spacer()
                    }
                    if !b.note.isEmpty { Label(b.note, systemImage: "info.circle").foregroundStyle(.secondary) }
                    if !b.behavior.present && !b.rate.present {
                        ContentUnavailableView("No baselines captured", systemImage: "chart.bar.doc.horizontal",
                            description: Text("Drift and rate anomaly checks need a baseline to compare against."))
                    }
                    HStack(alignment: .top, spacing: 12) { side(b.behavior); side(b.rate) }
                    if let g = b.generatedAt { Text("Computed \(CellFormat.relative(g))").font(.caption).foregroundStyle(.secondary) }
                }.padding()
            }
        }
        .linkFilter(text: $query)
    }

    private func side(_ s: PlatformData.BaselineSide) -> some View {
        KVSection(title: s.name, items: [
            ("Present", s.present ? "yes" : "no"),
            ("Entries", "\(s.entries)"),
            ("Captured", s.capturedAt.map { CellFormat.relative($0) } ?? ""),
            ("Age", s.present ? CellFormat.duration(s.ageSeconds) : ""),
        ])
    }
}

/// The P0-P5 observe surfaces: one picker over the read-only boards the web Surfaces page uses.
struct PlatSurfacesPage: View {
    @State private var group = PlatformData.groups[0]
    @State private var boardID = PlatformData.boards[0].id

    private var board: PlatformData.Board { PlatformData.boards.first { $0.id == boardID } ?? PlatformData.boards[0] }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("Group", selection: $group) { ForEach(PlatformData.groups, id: \.self) { Text($0).tag($0) } }
                    .pickerStyle(.segmented).labelsHidden().frame(maxWidth: 420)
                Picker("Board", selection: $boardID) { ForEach(PlatformData.boards(in: group)) { Text($0.label).tag($0.id) } }
                    .labelsHidden().frame(maxWidth: 220)
                Spacer()
            }
            .padding(8)
            .onChange(of: group) { _, g in if let f = PlatformData.boards(in: g).first { boardID = f.id } }
            PlatBoardView(board: board).id(board.id)
        }
    }
}

struct PlatBoardView: View {
    let board: PlatformData.Board
    @State private var selection: Int?
    @State private var query = ""

    var body: some View {
        JSONLoader(title: board.label, path: board.path, liveEvery: 20) { json in
            let all = PlatformData.pickList(json, keys: board.listKeys)
            let rows = Array(all.enumerated()).filter { _, r in
                query.isEmpty || PlatformData.rowLabel(r).localizedCaseInsensitiveContains(query) || PlatformData.rowMeta(r).localizedCaseInsensitiveContains(query)
            }
            let note = DetectData.str(json, "note")
            VStack(alignment: .leading, spacing: 0) {
                TextField("Filter", text: $query).textFieldStyle(.roundedBorder).padding(.horizontal).frame(maxWidth: 320)
                PlatNote(text: note)
                if rows.isEmpty {
                    ContentUnavailableView(all.isEmpty ? "Nothing to show" : "No matches", systemImage: "tray",
                        description: Text(all.isEmpty ? "This board has no rows, or its detector is not enabled." : "Try a different filter."))
                } else {
                    List(rows, id: \.offset, selection: $selection) { i, r in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(PlatformData.rowLabel(r).isEmpty ? "Row \(i + 1)" : PlatformData.rowLabel(r)).textSelection(.enabled)
                            let m = PlatformData.rowMeta(r)
                            if !m.isEmpty { Text(m).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
                        }
                    }
                }
            }.padding(.top, 4)
        }
        .linkFilter(text: $query)
    }
}
