// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Reusable guarded-mutation sheet: preview -> (typed phrase if high risk) -> confirm.
/// Everything is disabled for read-only roles; enforce changes show the live lease countdown.
struct MutationSheet<Extra: View>: View {
    @Bindable var flow: MutationFlow
    var onClose: () -> Void
    @ViewBuilder var extra: () -> Extra
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(flow.spec.title).font(.headline)
            extra()
            if !model.gate.canMutate {
                Label("This token is read-only. Mutations are disabled.", systemImage: "lock").foregroundStyle(.orange)
            }
            if flow.spec.leaseBound { leaseBanner }
            GroupBox("1. Preview (dry run)") {
                VStack(alignment: .leading) {
                    Button("Run preview") { Task { await flow.runPreview() } }.disabled(!flow.canPreview)
                    Text(flow.previewSummary ?? "A preview is required before you can confirm.")
                        .foregroundStyle(flow.previewed ? Color.primary : Color.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            if flow.effectiveRisk.requiresTypedConfirmation {
                GroupBox("2. Type to confirm (\(flow.effectiveRisk.rawValue) risk)") {
                    VStack(alignment: .leading) {
                        Text("Type: \(flow.spec.expectedPhrase)").font(.system(.body, design: .monospaced))
                        TextField("confirmation phrase", text: $flow.typedPhrase)
                            .disabled(!model.gate.canMutate || !flow.previewed)
                        Text("Sends X-Netra-Confirm-Risk: \(flow.effectiveRisk.confirmHeaderValue)").font(.caption).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            switch flow.phase {
            case .done(let m): Label(m, systemImage: "checkmark.circle").foregroundStyle(.green)
            case .failed(let m): Label(m, systemImage: "xmark.octagon").foregroundStyle(.red)
            case .running, .previewing: ProgressView().controlSize(.small)
            case .idle: EmptyView()
            }
            HStack {
                Spacer()
                Button("Close", action: onClose).keyboardShortcut(.cancelAction)
                Button("Confirm") { Task { await flow.confirm() } }
                    .keyboardShortcut(.defaultAction).disabled(!flow.canConfirm)
            }
        }
        .padding().frame(width: 460)
    }

    @ViewBuilder private var leaseBanner: some View {
        TimelineView(.periodic(from: .now, by: 1)) { ctx in
            let expires = model.lease?.leaseExpiresAt
            let t = LeaseTracker(expiresAt: expires)
            let enforcing = model.lease.map { t.effectiveMode(declared: $0.mode, now: ctx.date) == "enforce" } ?? false
            if enforcing {
                Label("Enforce lease: \(Int(t.remaining(now: ctx.date)))s remaining; fails open to observe at expiry.", systemImage: "timer")
                    .foregroundStyle(.orange)
            } else {
                Label("Not in enforce: this change is recorded but takes effect only under an enforce lease.", systemImage: "eye")
                    .foregroundStyle(.secondary)
            }
        }
    }
}
