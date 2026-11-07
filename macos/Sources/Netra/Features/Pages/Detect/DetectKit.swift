// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Colour for a severity. Always shown together with a symbol and the word, never colour alone.
func severityColor(_ s: String?) -> Color {
    switch DetectData.severityRank(s) {
    case 4: .red
    case 3: .orange
    case 2: .yellow
    case 1: .blue
    default: .secondary
    }
}

struct DetectSeverityBadge: View {
    let severity: String
    var body: some View {
        Label(severity.isEmpty ? "unknown" : severity.capitalized, systemImage: DetectData.severitySymbol(severity))
            .font(.caption.weight(.semibold))
            .foregroundStyle(severityColor(severity))
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(severityColor(severity).opacity(0.14), in: Capsule())
            .accessibilityLabel("Severity \(severity.isEmpty ? "unknown" : severity)")
    }
}

/// Fetches one GET endpoint (read-only), optionally refreshing while Live is on, and hands the JSON to `content`.
struct JSONLoader<Content: View>: View {
    let title: String
    let path: String
    var query: [URLQueryItem] = []
    var liveEvery: Double? = 10
    @ViewBuilder var content: (JSONValue) -> Content
    @Environment(AppModel.self) private var model
    @State private var value: JSONValue?
    @State private var error: String?
    @State private var loading = false
    @State private var live = false

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else if let value {
                content(value)
            } else if let error {
                ContentUnavailableView("Couldn't load \(title)", systemImage: "exclamationmark.triangle", description: Text(error))
            } else { ProgressView().controlSize(.large) }
        }
        .navigationTitle(title).navigationSubtitle(path)
        .toolbar {
            if liveEvery != nil { Toggle("Live", systemImage: "dot.radiowaves.left.and.right", isOn: $live) }
            Button("Refresh", systemImage: "arrow.clockwise") { Task { await load() } }.disabled(loading)
        }
        .task(id: path + query.map { "\($0.name)=\($0.value ?? "")" }.joined(separator: "&")) { await load() }
        .task(id: live) {
            guard live, let every = liveEvery else { return }
            while !Task.isCancelled { try? await Task.sleep(for: .seconds(every)); if Task.isCancelled { break }; await load() }
        }
    }

    private func load() async {
        guard let c = model.client else { return }
        loading = true; defer { loading = false }
        do {
            var req = c.request("GET", path, query: query)
            req.timeoutInterval = 20
            value = try JSONDecoder().decode(JSONValue.self, from: await c.send(req)); error = nil
        } catch NetraError.http(let s, let m) { error = "HTTP \(s): \(m)" }
        catch { self.error = error.localizedDescription }
    }
}

/// Small bar chart of counts by severity (used by several tabs).
struct SeverityBars: View {
    let counts: [(severity: String, count: Int)]
    var body: some View {
        HStack(spacing: 8) {
            ForEach(counts, id: \.severity) { c in
                HStack(spacing: 4) { DetectSeverityBadge(severity: c.severity); Text("\(c.count)").monospacedDigit().font(.callout.weight(.semibold)) }
            }
            Spacer()
        }
    }
}

/// Monospaced key/value block for an inspector.
struct InspectorText: View {
    let title: String
    let text: String
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(text.isEmpty ? "–" : text).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

func fmtTime(_ d: Date?) -> String { d.map { CellFormat.relative($0) } ?? "–" }
