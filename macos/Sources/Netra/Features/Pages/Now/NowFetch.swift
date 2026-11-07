// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit
import Charts

/// Loads one GET endpoint as schema-less JSON and hands it to `content`. Read-only; optional live refresh.
struct NowFetch<Content: View>: View {
    let title: String
    let endpoint: String
    var query: [URLQueryItem] = []
    var liveEvery: Double? = 5
    @ViewBuilder var content: (JSONValue) -> Content
    @Environment(AppModel.self) private var model
    @State private var value: JSONValue?
    @State private var error: String?
    @State private var loading = false
    @State private var live = false
    @State private var updated: Date?

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else if let value {
                ScrollView { content(value).padding() }
            } else if let error {
                ContentUnavailableView("Couldn't load \(title)", systemImage: "exclamationmark.triangle", description: Text(error))
            } else { ProgressView().controlSize(.large) }
        }
        .navigationTitle(title).navigationSubtitle(endpoint)
        .toolbar {
            if let updated { Text("Updated \(updated, style: .time)").font(.caption).foregroundStyle(.secondary) }
            if liveEvery != nil { Toggle("Live", systemImage: "dot.radiowaves.left.and.right", isOn: $live) }
            Button("Refresh", systemImage: "arrow.clockwise") { Task { await load() } }.disabled(loading)
        }
        .task(id: endpoint) { await load() }
        .task(id: live) {
            guard live, let every = liveEvery else { return }
            while !Task.isCancelled { try? await Task.sleep(for: .seconds(every)); if Task.isCancelled { break }; await load() }
        }
    }

    private func load() async {
        guard let c = model.client else { return }
        loading = true; defer { loading = false }
        do {
            var req = c.request("GET", endpoint, query: query); req.timeoutInterval = 20
            value = try JSONDecoder().decode(JSONValue.self, from: await c.send(req)); error = nil; updated = Date()
        } catch NetraError.http(let s, let m) { error = "HTTP \(s): \(m)" }
        catch { self.error = error.localizedDescription }
    }
}

/// Severity pill: symbol + word + colour.
struct NowBadge: View {
    let severity: NowSeverity
    var text: String? = nil
    var body: some View {
        Label(text ?? severity.label, systemImage: severity.symbol)
            .font(.caption.weight(.semibold)).foregroundStyle(severity.tint)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(severity.tint.opacity(0.14), in: Capsule())
            .accessibilityLabel("Status \(text ?? severity.label)")
    }
}

extension NowSeverity {
    var tint: Color {
        switch self {
        case .ok: .green; case .info: .blue; case .unknown: .secondary
        case .warning: .orange; case .high: .red; case .critical: .red
        }
    }
}

/// Horizontal bar chart of name/value pairs.

struct NowBars: View {
    let title: String
    let items: [NamedValue]
    var tint: Color = .accentColor
    var body: some View {
        GroupBox(title) {
            if items.isEmpty {
                Text("None observed").foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 60)
            } else {
                Chart(items) { item in
                    BarMark(x: .value("Count", item.value), y: .value("Name", item.name)).foregroundStyle(tint)
                        .annotation(position: .trailing) { Text(String(Int(item.value))).font(.caption2).foregroundStyle(.secondary) }
                }
                    .chartXAxis(.hidden)
                    .frame(height: CGFloat(max(items.count, 2)) * 26 + 10)
            }
        }
    }
}
