// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// In-memory log of attempted mutations (this session only).
struct ActivityPanel: View {
    var log: ActivityLog
    var body: some View {
        VStack(alignment: .leading) {
            Text("Activity").font(.headline).padding([.top, .horizontal])
            if log.entries.isEmpty {
                ContentUnavailableView("No mutations yet", systemImage: "list.bullet.rectangle")
            } else {
                List(log.entries) { e in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack {
                            Text(e.outcome.rawValue.uppercased()).font(.caption.bold()).foregroundStyle(color(e.outcome))
                            Text(e.at, style: .time).font(.caption).foregroundStyle(.secondary)
                        }
                        Text(e.title)
                        Text("\(e.method) \(e.path)").font(.caption.monospaced()).foregroundStyle(.secondary)
                        if !e.detail.isEmpty { Text(e.detail).font(.caption) }
                    }
                }
            }
        }
    }
    private func color(_ o: ActivityEntry.Outcome) -> Color {
        switch o { case .succeeded: .green; case .failed: .red; case .blocked: .orange; case .attempted: .blue }
    }
}
