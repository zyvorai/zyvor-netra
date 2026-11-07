// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

extension KernelData.Severity {
    var tint: Color { [Color.red, .orange, .blue, .green][rawValue] }
}

/// Severity shown as symbol plus text, never colour alone.
struct SeverityLabel: View {
    let severity: KernelData.Severity
    var text: String? = nil
    var body: some View {
        Label(text ?? severity.label, systemImage: severity.symbol).foregroundStyle(severity.tint).lineLimit(1)
            .accessibilityLabel("\(severity.label)\(text.map { ": \($0)" } ?? "")")
    }
}

/// A horizontal fill bar with a text value; colour follows pressure and the percentage is always printed.
struct FillBar: View {
    let ratio: Double?
    var detail: String? = nil
    var body: some View {
        HStack(spacing: 6) {
            if let r = ratio {
                let level = KernelData.pressure(r)
                ProgressView(value: min(r, 1)).tint(level.tint).frame(minWidth: 60, maxWidth: 140)
                Text(String(format: "%.0f%%", r * 100)).monospacedDigit().frame(minWidth: 38, alignment: .trailing)
                if level != .ok { Image(systemName: level.symbol).foregroundStyle(level.tint).accessibilityHidden(true) }
            } else { Text("–").foregroundStyle(.secondary) }
            if let detail { Text(detail).foregroundStyle(.secondary).font(.caption).lineLimit(1) }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(ratio.map { String(format: "%.0f percent full", $0 * 100) + (detail.map { ", \($0)" } ?? "") } ?? "unknown")
    }
}

/// Loads one primary endpoint (plus optional secondary ones whose failures are tolerated), with
/// refresh, an optional live toggle, and clear not-connected / error / loading states.
struct KernelLoader<Content: View>: View {
    let title: String
    let endpoint: String
    var query: [URLQueryItem] = []
    var secondary: [(path: String, query: [URLQueryItem])] = []
    var liveEvery: Double? = nil
    @ViewBuilder var content: (_ primary: JSONValue, _ secondary: [JSONValue?]) -> Content

    @Environment(AppModel.self) private var model
    @State private var primary: JSONValue?
    @State private var extras: [JSONValue?] = []
    @State private var error: String?
    @State private var loading = false
    @State private var live = false
    @State private var updated: Date?

    private var key: String { endpoint + (query.map { "\($0.name)=\($0.value ?? "")" }.joined(separator: "&")) }

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else if let primary {
                content(primary, extras)
            } else if let error {
                ContentUnavailableView("Couldn't load \(title)", systemImage: "exclamationmark.triangle", description: Text(error))
            } else { ProgressView().controlSize(.large) }
        }
        .navigationTitle(title)
        .navigationSubtitle(updated.map { "\(endpoint) · updated \($0.formatted(date: .omitted, time: .standard))" } ?? endpoint)
        .toolbar {
            if liveEvery != nil { Toggle("Live", systemImage: "dot.radiowaves.left.and.right", isOn: $live) }
            Button("Refresh", systemImage: "arrow.clockwise") { Task { await load() } }.disabled(loading)
        }
        .task(id: key) { await load() }
        .task(id: live) {
            guard live, let every = liveEvery else { return }
            while !Task.isCancelled { try? await Task.sleep(for: .seconds(every)); if Task.isCancelled { break }; await load() }
        }
    }

    private func get(_ c: NetraClient, _ path: String, _ q: [URLQueryItem]) async throws -> JSONValue {
        var req = c.request("GET", path, query: q)
        req.timeoutInterval = 20
        return try JSONDecoder().decode(JSONValue.self, from: await c.send(req))
    }

    private func load() async {
        guard let c = model.client else { return }
        loading = true; defer { loading = false }
        do {
            primary = try await get(c, endpoint, query); error = nil; updated = Date()
        } catch NetraError.http(let s, let m) { error = "HTTP \(s): \(m)"; return }
        catch { self.error = error.localizedDescription; return }
        var out: [JSONValue?] = []
        for s in secondary { out.append(try? await get(c, s.path, s.query)) }
        extras = out
    }
}

/// Shared empty-state for lists inside a page.
struct KernelEmpty: View {
    let text: String
    var symbol = "tray"
    var body: some View { ContentUnavailableView(text, systemImage: symbol).frame(maxWidth: .infinity, minHeight: 120) }
}

/// Read-only JSON text for the inspector panes.
struct KernelRawJSON: View {
    let value: JSONValue
    var body: some View {
        ScrollView {
            Text(text).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading).padding()
        }
    }
    private var text: String {
        let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return (try? e.encode(value)).map { String(decoding: $0, as: UTF8.self) } ?? value.summary
    }
}
