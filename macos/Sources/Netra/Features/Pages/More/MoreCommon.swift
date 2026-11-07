// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// One GET with the friendly error mapping. Read-only.
enum MoreFetch {
    static func get(_ c: NetraClient, _ path: String, query: [URLQueryItem] = [], feature: String) async -> Result<JSONValue, MoreFailure> {
        do {
            var req = c.request("GET", path, query: query)
            req.timeoutInterval = 20
            return .success(try JSONDecoder().decode(JSONValue.self, from: await c.send(req)))
        } catch NetraError.http(let s, let m) {
            return .failure(MoreFailure(text: MoreData.friendlyError(status: s, message: m, feature: feature), featureOff: s == 404 || s == 409))
        } catch {
            return .failure(MoreFailure(text: error.localizedDescription, featureOff: false))
        }
    }
}

struct MoreFailure: Error { let text: String; let featureOff: Bool }

/// Loads one primary endpoint plus optional secondary ones (their failures are tolerated and passed as nil).
struct MoreLoader<Content: View>: View {
    let title: String
    let endpoint: String
    var query: [URLQueryItem] = []
    var secondary: [(path: String, query: [URLQueryItem])] = []
    var liveEvery: Double? = nil
    @ViewBuilder var content: (_ primary: JSONValue, _ secondary: [JSONValue?]) -> Content

    @Environment(AppModel.self) private var model
    @State private var primary: JSONValue?
    @State private var extras: [JSONValue?] = []
    @State private var failure: MoreFailure?
    @State private var loading = false
    @State private var live = false
    @State private var updated: Date?

    private var key: String { endpoint + query.map { "\($0.name)=\($0.value ?? "")" }.joined(separator: "&") }

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else if let primary {
                VStack(spacing: 0) {
                    if let failure { MoreBanner(text: "Showing the last good data. Refresh failed: \(failure.text)") }
                    content(primary, extras)
                }
            } else if let failure {
                ContentUnavailableView(failure.featureOff ? "\(title) is off" : "Couldn't load \(title)",
                                       systemImage: failure.featureOff ? "power.dotted" : "exclamationmark.triangle", description: Text(failure.text))
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

    private func load() async {
        guard let c = model.client else { return }
        loading = true; defer { loading = false }
        switch await MoreFetch.get(c, endpoint, query: query, feature: title) {
        case .success(let v): primary = v; failure = nil; updated = Date()
        case .failure(let f): failure = f; return
        }
        var out: [JSONValue?] = []
        for s in secondary { out.append(try? await MoreFetch.get(c, s.path, query: s.query, feature: title).get()) }
        extras = out
    }
}

struct MoreBanner: View {
    let text: String
    var symbol = "exclamationmark.triangle.fill"
    var tint: Color = .orange
    var body: some View {
        Label(text, systemImage: symbol).font(.callout).foregroundStyle(tint)
            .padding(8).frame(maxWidth: .infinity, alignment: .leading).background(tint.opacity(0.1))
    }
}

/// Filterable, sortable table of already-built rows with a read-only JSON inspector.
struct MoreRowsTable: View {
    let rows: [ControlRow]
    let columns: [PageColumn]
    var empty = "Nothing to show right now."
    @State private var query = ""
    @State private var sort: [ColumnComparator] = []
    @State private var selection: ControlRow.ID?

    private var shown: [ControlRow] {
        var r = rows
        if !query.isEmpty { r = r.filter { row in columns.contains { CellFormat.text(row.value.at($0.path), $0.kind).localizedCaseInsensitiveContains(query) } } }
        return r.sorted(using: sort)
    }

    var body: some View {
        let r = shown
        HSplitView {
            if r.isEmpty {
                ContentUnavailableView(query.isEmpty ? empty : "No matches", systemImage: "tray")
            } else {
                Table(r, selection: $selection, sortOrder: $sort) {
                    TableColumnForEach(columns) { c in
                        TableColumn(c.title, sortUsing: ColumnComparator(path: c.path, kind: c.kind)) { (row: ControlRow) in
                            Text(CellFormat.text(row.value.at(c.path), c.kind)).lineLimit(1)
                        }.width(min: c.width ?? 60)
                    }
                }
            }
            Group {
                if let row = r.first(where: { $0.id == selection }) { KernelRawJSON(value: row.value) }
                else { ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select a row to inspect.")) }
            }.frame(minWidth: 240, idealWidth: 300)
        }
        .searchable(text: $query, prompt: "Filter")
        .linkFilter(text: $query)
    }
}

/// A titled list of plain strings (limitations, next steps, notes).
struct MoreBullets: View {
    let title: String
    let items: [String]
    var symbol = "circle.fill"
    var body: some View {
        if !items.isEmpty {
            GroupBox(title) {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(items.enumerated()), id: \.offset) { _, s in
                        Label { Text(s).textSelection(.enabled) } icon: { Image(systemName: symbol).font(.system(size: 5)) }
                            .labelStyle(.titleAndIcon)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.padding(.horizontal).padding(.bottom, 8)
        }
    }
}

/// Severity or confidence as symbol plus text, never colour alone.
struct MoreLevel: View {
    let text: String
    var body: some View {
        let rank = TrafficData.severityRank(text)
        Label(text.isEmpty ? "unknown" : text, systemImage: rank >= 3 ? "exclamationmark.octagon.fill" : rank == 2 ? "exclamationmark.triangle.fill" : "info.circle")
            .foregroundStyle(rank >= 3 ? Color.red : rank == 2 ? .orange : .secondary)
    }
}
