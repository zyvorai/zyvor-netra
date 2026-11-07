// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// One failed read: text for the user and whether it means the feature is off on this controller.
struct CovFailure: Error { let text: String; let featureOff: Bool }

/// One GET with the friendly error mapping. Read-only: the verb is fixed.
enum CovFetch {
    static func get(_ c: NetraClient, _ path: String, query: [URLQueryItem] = [], feature: String) async -> Result<JSONValue, CovFailure> {
        do {
            var req = c.request("GET", path, query: query)
            req.timeoutInterval = 20
            return .success(try JSONDecoder().decode(JSONValue.self, from: await c.send(req)))
        } catch NetraError.http(let s, let m) {
            return .failure(CovFailure(text: CoverageData.friendlyError(status: s, message: m, feature: feature), featureOff: CoverageData.isFeatureOff(status: s)))
        } catch {
            return .failure(CovFailure(text: error.localizedDescription, featureOff: false))
        }
    }
}

/// Loads one GET endpoint with refresh and an optional Live toggle; 404/409/503 render as "<feature> is off".
struct CovLoader<Content: View>: View {
    let title: String
    let endpoint: String
    var query: [URLQueryItem] = []
    var liveEvery: Double? = nil
    @ViewBuilder var content: (JSONValue) -> Content

    @Environment(AppModel.self) private var model
    @State private var value: JSONValue?
    @State private var failure: CovFailure?
    @State private var loading = false
    @State private var live = false

    private var key: String { endpoint + query.map { "\($0.name)=\($0.value ?? "")" }.joined(separator: "&") }

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else if let value {
                VStack(spacing: 0) {
                    if let failure {
                        Label("Showing the last good data. Refresh failed: \(failure.text)", systemImage: "exclamationmark.triangle.fill")
                            .font(.callout).foregroundStyle(.orange).padding(8).frame(maxWidth: .infinity, alignment: .leading).background(.orange.opacity(0.1))
                    }
                    content(value)
                }
            } else if let failure {
                ContentUnavailableView(failure.featureOff ? "\(title) is off" : "Couldn't load \(title)",
                                       systemImage: failure.featureOff ? "power.dotted" : "exclamationmark.triangle", description: Text(failure.text))
            } else { ProgressView().controlSize(.large) }
        }
        .navigationTitle(title).navigationSubtitle(endpoint)
        .toolbar {
            if liveEvery != nil { Toggle("Live", systemImage: "dot.radiowaves.left.and.right", isOn: $live) }
            Button("Refresh", systemImage: "arrow.clockwise") { Task { await load() } }.disabled(loading)
        }
        .task(id: key) { value = nil; failure = nil; await load() }
        .task(id: live) {
            guard live, let every = liveEvery else { return }
            while !Task.isCancelled { try? await Task.sleep(for: .seconds(every)); if Task.isCancelled { break }; await load() }
        }
    }

    private func load() async {
        guard let c = model.client else { return }
        loading = true; defer { loading = false }
        switch await CovFetch.get(c, endpoint, query: query, feature: title) {
        case .success(let v): value = v; failure = nil
        case .failure(let f): failure = f
        }
    }
}

/// Horizontal tab bar over a CaseIterable enum (same look as the Insights page).
struct CovTabBar<Tab: CaseIterable & Hashable & RawRepresentable>: View where Tab.RawValue == String, Tab.AllCases: RandomAccessCollection {
    @Binding var tab: Tab
    var body: some View {
        VStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ForEach(Array(Tab.allCases), id: \.self) { t in
                        Button(t.rawValue) { tab = t }
                            .buttonStyle(.bordered).controlSize(.small)
                            .tint(t == tab ? .accentColor : .secondary)
                            .accessibilityAddTraits(t == tab ? .isSelected : [])
                    }
                }.padding(8)
            }
            Divider()
        }
    }
}

/// Limitation/note lines the controller attaches to a response; always shown so an empty list is not misread.
struct CovNotes: View {
    let lines: [String]
    var body: some View {
        if !lines.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                ForEach(Array(lines.enumerated()), id: \.offset) { _, l in
                    Label(l, systemImage: "info.circle").font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }.padding(.horizontal).padding(.vertical, 6).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

/// Sortable, filterable table over already-extracted rows with a JSON inspector for the selected row.
struct CovTable: View {
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
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "line.3.horizontal.decrease").foregroundStyle(.secondary)
                TextField("Filter", text: $query).textFieldStyle(.roundedBorder).frame(maxWidth: 260)
                Spacer()
                Text("\(shown.count) of \(rows.count)").font(.caption).foregroundStyle(.secondary).monospacedDigit()
            }.padding(.horizontal).padding(.vertical, 6)
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
                CovInspector(row: r.first { $0.id == selection }).frame(minWidth: 240, idealWidth: 300)
            }
        }
    }
}

struct CovInspector: View {
    let row: ControlRow?
    var body: some View {
        ScrollView {
            if let row {
                Text(pretty(row.value)).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading).padding()
            } else { ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select a row to inspect.")) }
        }
    }
    private func pretty(_ v: JSONValue) -> String {
        let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return (try? e.encode(v)).map { String(decoding: $0, as: UTF8.self) } ?? v.summary
    }
}

/// Stat cards plus a table: the shape most coverage tabs share.
struct CovRowsView: View {
    let json: JSONValue
    let rows: [ControlRow]
    let stats: [PageStat]
    let columns: [PageColumn]
    var empty = "Nothing to show right now."
    var notes: [String] = []
    var body: some View {
        VStack(spacing: 0) {
            if !stats.isEmpty { StatRow(stats: stats, value: json).padding([.horizontal, .top]) }
            CovNotes(lines: notes)
            CovTable(rows: rows, columns: columns, empty: empty)
        }
    }
}
