// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

struct MenuBarView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: model.effectiveMode == "enforce" ? "shield.lefthalf.filled" : "eye")
                Text(model.effectiveMode.capitalized).font(.headline)
                Spacer()
                if let h = model.healthScore { Text("Health \(Int(h))").monospacedDigit().foregroundStyle(.secondary) }
            }
            if let l = model.lease, l.active { LeaseCountdown(lease: l, fetched: model.leaseFetchedAt) }
            Divider()
            Button("Open Netra") { NSApp.activate(ignoringOtherApps: true); openWindow(id: "main") }
            Button("Reconnect") { Task { await model.connect() } }
            Divider()
            Button("Quit") { NSApp.terminate(nil) }.keyboardShortcut("q")
        }
        .padding(14).frame(width: 280)
    }
}
