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

/// Compact, inline version of the trust prompt shown inside the connect form, so the certificate check
/// and the sign-in happen on one screen. Trusting pins this exact leaf fingerprint for the host.
struct TrustCard: View {
    let probe: CertificateProbeResult
    let onTrust: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Untrusted certificate", systemImage: "exclamationmark.shield.fill")
                .font(.headline).foregroundStyle(.orange)
            Text("\(probe.host):\(probe.port) presents a certificate your Mac doesn't trust. Compare this fingerprint with the controller's before trusting.")
                .font(.callout)
            Text(probe.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            HStack(spacing: 6) {
                Text(probe.subject).font(.caption).foregroundStyle(.secondary)
                if let na = probe.notAfter { Text("· valid until \(na.formatted(date: .abbreviated, time: .omitted))").font(.caption).foregroundStyle(.secondary) }
            }
            HStack {
                Spacer()
                Button("Don't trust", role: .cancel, action: onCancel)
                Button("Trust & connect", action: onTrust).buttonStyle(.borderedProminent)
            }
        }
        .padding(12)
        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(.orange.opacity(0.5)))
    }
}
