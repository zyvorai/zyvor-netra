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

/// Live per-second feed for one chart query over the metrics WebSocket (observe-only).
/// While it is delivering, callers skip their 5s poll; if the socket fails they poll as before.
@MainActor @Observable
final class LiveFeed {
    enum Mode: Equatable { case idle, connecting, live, reconnecting(String), failed(String), paused, unsupported }
    var mode: Mode = .idle
    var result: MetricResult?
    var lastFrame: Date?
    var paused = false

    /// True while frames are arriving; the poll loop yields to the socket.
    var delivering: Bool {
        guard mode == .live, let t = lastFrame else { return false }
        return Date().timeIntervalSince(t) < 4
    }

    /// Runs until cancelled (use from `.task(id:)`). Ranges beyond the stream limit poll instead.
    func run(client: NetraClient, context: String, seconds: Int, nodes: [String]) async {
        result = nil; lastFrame = nil
        if paused { mode = .paused; return }
        guard seconds <= MetricsLive.maxStreamWindow else { mode = .unsupported; return }
        let sub = LiveSubscription(id: LiveSubscription.id(context: context, node: nodes.first, chart: nil),
                                   context: context, nodes: nodes.isEmpty ? nil : nodes, window: Int64(seconds))
        mode = .connecting
        do {
            for try await u in WSClient.metrics(client: client, subscriptions: { [sub] }) {
                switch u {
                case .state(.connecting): if mode != .live { mode = .connecting }
                case .state(.live): mode = .live
                case .state(.reconnecting(_, _, let why)): mode = .reconnecting(why)
                case .message(let f):
                    if let r = f.results[sub.id] { result = r; lastFrame = Date() }
                }
            }
        } catch is CancellationError { return } catch {
            mode = .failed((error as? NetraError) == .unauthorized ? "Unauthorized" : error.localizedDescription)
        }
    }
}

struct LiveBadge: View {
    let feed: LiveFeed
    var body: some View {
        HStack(spacing: 6) {
            switch feed.mode {
            case .live where feed.delivering: StatusBadge(text: "Live", tint: .green)
            case .paused: StatusBadge(text: "Paused", tint: .secondary)
            case .connecting: StatusBadge(text: "Connecting", tint: .secondary)
            case .unsupported: StatusBadge(text: "Polling 5s (range > 1h)", tint: .secondary)
            case .failed, .reconnecting, .live, .idle: StatusBadge(text: "Polling 5s (socket down)", tint: .orange)
            }
            Button(feed.paused ? "Resume" : "Pause") { feed.paused.toggle() }
                .buttonStyle(.borderless).font(.caption)
                .accessibilityLabel(feed.paused ? "Resume live updates" : "Pause live updates")
        }
    }
}
