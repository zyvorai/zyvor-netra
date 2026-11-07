// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

struct MenuBarView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    @State private var log = ActivityLog()
    /// Set while the guarded "Return to observe" flow is waiting for confirmation.
    @State private var revert: MutationFlow?

    private var enforcing: Bool { model.effectiveMode == "enforce" }

    private var healthColor: Color {
        guard case .connected = model.connection, let h = model.healthScore else { return .gray }
        return h >= 80 ? .green : (h >= 50 ? .orange : .red)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Circle().fill(healthColor).frame(width: 9, height: 9)
                    .accessibilityLabel(model.healthScore.map { "Health \(Int($0))" } ?? "Health unknown")
                Image(systemName: enforcing ? "shield.lefthalf.filled" : "eye")
                Text(model.effectiveMode.capitalized).font(.headline)
                Spacer()
                if let h = model.healthScore { Text("Health \(Int(h))").monospacedDigit().foregroundStyle(.secondary) }
            }
            if let l = model.lease, l.active, enforcing { LeaseCountdown(lease: l, fetched: model.leaseFetchedAt) }
            if let a = model.topAlert {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: DetectData.severitySymbol(a.status)).foregroundStyle(a.status == "critical" ? .red : .orange)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(a.rule).font(.callout.weight(.medium)).lineLimit(2)
                        Text("\(a.status.capitalized)\(a.node.isEmpty ? "" : " · \(a.node)")").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            Divider()
            Button("Open Netra") { NSApp.activate(ignoringOtherApps: true); openWindow(id: "main") }
            if enforcing, model.gate.canMutate {
                if let f = revert { RevertConfirm(flow: f) { revert = nil } }
                else { Button("Return to observe…") { beginRevert() } }
            }
            Button("Reconnect") { Task { await model.connect() } }
            Divider()
            Button("Quit") { NSApp.terminate(nil) }.keyboardShortcut("q")
        }
        .padding(14).frame(width: 280)
    }

    /// Same spec and MutationFlow as the Enforcement page: a read-only preview first, then an explicit confirm.
    private func beginRevert() {
        guard let c = model.client else { return }
        let f = MutationFlow(spec: ControlMutations.modeSpec(client: c, enforce: false, leaseMinutes: 1), client: c, gate: model.gate, log: log)
        revert = f
        Task { await f.runPreview() }
    }
}

private struct RevertConfirm: View {
    let flow: MutationFlow
    let done: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            switch flow.phase {
            case .done(let m): Text("Returned to observe (\(m))").font(.caption)
            case .failed(let m): Text(m).font(.caption).foregroundStyle(.red)
            default: Text(flow.previewSummary ?? "Checking current mode…").font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                if case .done = flow.phase {} else {
                    Button("Confirm") { Task { await flow.confirm() } }.disabled(!flow.canConfirm)
                }
                Button("Dismiss", action: done)
            }
        }
    }
}
