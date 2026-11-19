// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

/// A small status line at the bottom of the main window. Informational only: it never blocks or disables anything.
struct LicenceStatusBar: View {
    @Environment(\.openWindow) private var openWindow
    private let licence = LicenceManager.shared

    var body: some View {
        let s = licence.state
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 8) {
                Image(systemName: s.needsAttention ? "exclamationmark.triangle.fill" : "key")
                    .foregroundStyle(s.needsAttention ? Color.orange : Color.secondary).imageScale(.small)
                Text(s.statusText).font(.caption).foregroundStyle(s.needsAttention ? Color.primary : Color.secondary).lineLimit(1).truncationMode(.tail)
                if s.showsTrialNote {
                    Text("Free 30-day trial key:").font(.caption).foregroundStyle(.secondary)
                    Link("sales@zyvor.dev", destination: LicenceState.trialURL).font(.caption)
                }
                Spacer()
                if s.showsBuyLink { Link("Get a licence", destination: LicenceState.buyURL).font(.caption) }
                Button("Licence…") { openWindow(id: "licence") }.buttonStyle(.link).font(.caption)
            }
            .padding(.horizontal, 12).padding(.vertical, 4)
            .background(.bar)
        }
    }
}

/// Netra > Licence…: paste a key, verify and save it, see what it grants, remove it.
struct LicenceView: View {
    private let licence = LicenceManager.shared
    @State private var pasted = ""
    @State private var message: String?
    @State private var messageIsError = false
    @State private var confirmRemove = false

    var body: some View {
        let s = licence.state
        VStack(alignment: .leading, spacing: 14) {
            Text("Licence").font(.title2.bold())
            Label(s.statusText, systemImage: s.needsAttention ? "exclamationmark.triangle.fill" : "key")
                .foregroundStyle(s.needsAttention ? Color.orange : Color.primary)
            if let c = s.claims {
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 4) {
                    GridRow { Text("Licensee").foregroundStyle(.secondary); Text(c.licensee).textSelection(.enabled) }
                    GridRow { Text("Edition").foregroundStyle(.secondary); Text(s.editionName ?? "") }
                    GridRow { Text("Expires").foregroundStyle(.secondary); Text(LicenceState.dateText(c.expires)) }
                    GridRow { Text("Days left").foregroundStyle(.secondary); Text(daysLeft(s)) }
                }
            }
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    Text(s.claims == nil ? "Paste your licence key" : "Replace the key").font(.headline)
                    TextEditor(text: $pasted).font(.system(.caption, design: .monospaced)).frame(height: 84)
                        .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
                    HStack {
                        if let message { Text(message).font(.callout).foregroundStyle(messageIsError ? Color.red : Color.green) }
                        Spacer()
                        Button("Verify and Save") { verify() }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                            .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                    Text("Keys look like ZYV1.… and are checked on this Mac. Nothing is sent anywhere.").font(.caption).foregroundStyle(.secondary)
                }.padding(4)
            }
            HStack {
                Link("Get a licence", destination: LicenceState.buyURL)
                Link("Free 30-day trial key: sales@zyvor.dev", destination: LicenceState.trialURL)
                Spacer()
                Button("Remove Key…", role: .destructive) { confirmRemove = true }.disabled(s == .unlicensed)
            }.font(.callout)
            Text("\(LicenceState.freeNote). Netra keeps working without a key.").font(.caption).foregroundStyle(.secondary)
        }
        .padding(22).frame(width: 520)
        .confirmationDialog("Remove the licence key from this Mac?", isPresented: $confirmRemove) {
            Button("Remove Key", role: .destructive) { licence.remove(); message = nil; pasted = "" }
        } message: { Text("Netra keeps working; it will show as having no licence key.") }
    }

    private func daysLeft(_ s: LicenceState) -> String {
        switch s { case .trial(let n, _), .pro(let n, _): return "\(n)"; default: return "0 (expired)" }
    }

    private func verify() {
        if let err = licence.activate(pasted) { message = err; messageIsError = true }
        else { message = "Saved. " + licence.state.statusText; messageIsError = false; pasted = "" }
    }
}
