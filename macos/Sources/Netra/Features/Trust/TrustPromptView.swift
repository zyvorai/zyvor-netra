// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

/// Sheet asking the user whether to trust a self-signed controller certificate.
struct TrustPrompt: View {
    let probe: CertificateProbeResult
    let onTrust: () -> Void
    let onCancel: () -> Void

    private var shortFP: String { probe.fingerprint.split(separator: ":").prefix(8).joined(separator: ":") + "…" }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Untrusted certificate", systemImage: "exclamationmark.shield.fill")
                .font(.title2.bold()).foregroundStyle(.orange)
            Text("\(probe.host):\(probe.port) presents an untrusted certificate: SHA-256 \(shortFP). Trust it?")
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                GridRow { Text("Subject").foregroundStyle(.secondary); Text(probe.subject).textSelection(.enabled) }
                GridRow { Text("Valid from").foregroundStyle(.secondary); Text(probe.notBefore.map(Self.fmt) ?? "unknown") }
                GridRow { Text("Valid until").foregroundStyle(.secondary); Text(probe.notAfter.map(Self.fmt) ?? "unknown") }
                GridRow(alignment: .top) {
                    Text("SHA-256").foregroundStyle(.secondary)
                    Text(probe.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                }
            }
            Text("Compare this fingerprint with the one your administrator published. If trusted, future connections must present this exact certificate.")
                .font(.footnote).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel).keyboardShortcut(.cancelAction)
                Button("Trust Certificate", action: onTrust)
            }
        }
        .padding(20).frame(width: 480)
    }

    private static func fmt(_ d: Date) -> String { d.formatted(date: .abbreviated, time: .omitted) }
}
