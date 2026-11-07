// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Loads/refreshes a value every `interval` seconds until the view disappears.
@MainActor @Observable
final class Poller<T: Sendable> {
    var value: T?
    var error: String?
    var loading = false

    func message(_ e: Error) -> String {
        switch e {
        case NetraError.http(let s, let m): s == 503 ? "Unavailable: \(m)" : "HTTP \(s): \(m)"
        case NetraError.unauthorized: "Unauthorized: check the API token"
        case NetraError.transport(let m): "Cannot reach controller: \(m)"
        default: e.localizedDescription
        }
    }

    func refresh(_ op: @Sendable () async throws -> T) async {
        loading = true
        defer { loading = false }
        do { value = try await op(); error = nil } catch is CancellationError { return } catch { self.error = message(error) }
    }
}

struct StatusBadge: View {
    let text: String
    let tint: Color
    var body: some View {
        Text(text).font(.caption2.weight(.semibold))
            .padding(.horizontal, 7).padding(.vertical, 2)
            .foregroundStyle(tint)
            .background(tint.opacity(0.14), in: Capsule())
            .overlay(Capsule().strokeBorder(tint.opacity(0.35)))
            .accessibilityLabel(text)
    }
}

extension MetricRanked.Severity {
    var tint: Color { switch self { case .high: .red; case .elevated: .orange; case .low: .secondary } }
}

func alertTint(_ status: String) -> Color {
    switch status { case "critical": .red; case "warning": .orange; default: .secondary }
}

struct ErrorBanner: View {
    let text: String
    var body: some View {
        Label(text, systemImage: "exclamationmark.triangle")
            .font(.callout).foregroundStyle(.orange)
            .padding(8).frame(maxWidth: .infinity, alignment: .leading)
            .background(.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
    }
}

struct RangePicker: View {
    @Binding var range: MetricRange
    var body: some View {
        Picker("Range", selection: $range) {
            ForEach(MetricRange.allCases) { Text($0.rawValue).tag($0) }
        }
        .pickerStyle(.segmented).labelsHidden().frame(width: 230)
        .accessibilityLabel("Time range")
    }
}

func relative(_ iso: String?) -> String {
    guard let d = MetricsFormat.parseTime(iso) else { return iso ?? "" }
    return d.formatted(.relative(presentation: .named))
}
