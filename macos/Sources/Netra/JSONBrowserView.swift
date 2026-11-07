// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

/// Live, searchable tree of any read endpoint. Every sidebar section works through this
/// until its bespoke view lands, and it stays useful as a raw-response inspector.
struct JSONBrowserView: View {
    @Environment(AppModel.self) private var model
    let section: NavSection
    @State private var value: JSONValue?
    @State private var loadError: String?
    @State private var loading = false
    @State private var query = ""

    var body: some View {
        Group {
            if let v = value {
                List { JSONNode(key: nil, value: v, query: query.lowercased(), root: true) }
            } else if let e = loadError {
                ContentUnavailableView("Couldn't load \(section.title)", systemImage: "exclamationmark.triangle", description: Text(e))
            } else { ProgressView().controlSize(.large) }
        }
        .navigationTitle(section.title)
        .navigationSubtitle(section.endpoint ?? "")
        .searchable(text: $query, prompt: "Filter keys and values")
        .toolbar { Button { Task { await load() } } label: { Label("Refresh", systemImage: "arrow.clockwise") }.disabled(loading) }
        .task { await load() }
    }

    private func load() async {
        guard let c = model.client, let ep = section.endpoint else { return }
        loading = true; defer { loading = false }
        do { value = try await c.json(ep); loadError = nil }
        catch NetraError.http(let s, let m) { loadError = "HTTP \(s): \(m)"; value = nil }
        catch { loadError = error.localizedDescription }
    }
}

struct JSONNode: View {
    let key: String?, value: JSONValue, query: String
    var root = false

    var body: some View {
        switch value {
        case .object(let o):
            let items = o.keys.sorted().filter { matches(o[$0]!, $0) }
            DisclosureGroup(isExpanded: .constant(root || !query.isEmpty)) {
                ForEach(items, id: \.self) { JSONNode(key: $0, value: o[$0]!, query: query) }
            } label: { label }
        case .array(let a):
            DisclosureGroup {
                ForEach(Array(a.enumerated()), id: \.offset) { i, v in JSONNode(key: "[\(i)]", value: v, query: query) }
            } label: { label }
        default:
            HStack { Text(key ?? "").foregroundStyle(.secondary); Spacer(); Text(value.summary).textSelection(.enabled).monospaced() }
        }
    }
    private var label: some View {
        HStack { Text(key ?? "response").fontWeight(.medium); Text(value.summary).foregroundStyle(.secondary) }
    }
    private func matches(_ v: JSONValue, _ k: String) -> Bool {
        query.isEmpty || k.lowercased().contains(query) || v.summary.lowercased().contains(query)
            || { if case .object(let o) = v { return o.contains { matches($1, $0) } }; if case .array(let a) = v { return a.contains { matches($0, "") } }; return false }()
    }
}
