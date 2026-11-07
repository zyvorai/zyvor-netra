// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// One table column: a dotted path into each row plus how to show and sort it.
struct PageColumn: Identifiable {
    let title: String
    let path: String
    var kind: CellKind = .text
    var width: CGFloat? = nil
    var id: String { path + title }
}

/// A headline number above a table. `value` reads the whole response, so it can also count rows.
struct PageStat: Identifiable {
    let title: String
    var symbol: String? = nil
    var tint: Color = .accentColor
    let value: (JSONValue) -> String
    var id: String { title }
}

/// Where the rows live and how to read them. Most observe pages are just one of these.
struct PageConfig {
    var title: String
    var endpoint: String
    var query: [URLQueryItem] = []
    /// Dotted path to the array of rows ("" when the response is the array). `rowFallbacks` are tried next.
    var rowsPath = ""
    var rowFallbacks: [String] = []
    /// Use when the rows are an object keyed by name rather than an array.
    var rowsAreMap = false
    var idKeys = ["id", "name"]
    var columns: [PageColumn]
    var stats: [PageStat] = []
    /// Seconds between automatic refreshes while Live is on; nil = manual only.
    var liveEvery: Double? = 5
    var emptyText = "Nothing to show right now."
}

/// Generic live table page: stat cards, search, sortable columns, a JSON inspector, optional extra header.
struct DataPageView<Header: View>: View {
    let config: PageConfig
    @ViewBuilder var header: (JSONValue) -> Header
    @Environment(AppModel.self) private var model
    @State private var value: JSONValue?
    @State private var error: String?
    @State private var loading = false
    @State private var query = ""
    @State private var live = false
    @State private var sort: [ColumnComparator] = []
    @State private var selection: ControlRow.ID?

    init(_ config: PageConfig, @ViewBuilder header: @escaping (JSONValue) -> Header = { _ in EmptyView() }) {
        self.config = config; self.header = header
    }

    private var rows: [ControlRow] {
        guard let value else { return [] }
        var r = config.rowsAreMap ? value.mapRows(at: config.rowsPath) : value.rows(at: config.rowsPath, fallbacks: config.rowFallbacks, idKeys: config.idKeys)
        if !query.isEmpty { r = r.filter { row in config.columns.contains { CellFormat.text(row.value.at($0.path), $0.kind).localizedCaseInsensitiveContains(query) } } }
        return r.sorted(using: sort)
    }

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else if let value {
                VStack(spacing: 0) {
                    if !config.stats.isEmpty { StatRow(stats: config.stats, value: value).padding([.horizontal, .top]) }
                    header(value)
                    let r = rows
                    HSplitView {
                        if r.isEmpty {
                            ContentUnavailableView(query.isEmpty ? config.emptyText : "No matches", systemImage: "tray")
                        } else {
                            Table(r, selection: $selection, sortOrder: $sort) {
                                TableColumnForEach(config.columns) { c in
                                    TableColumn(c.title, sortUsing: ColumnComparator(path: c.path, kind: c.kind)) { (row: ControlRow) in
                                        Text(CellFormat.text(row.value.at(c.path), c.kind)).lineLimit(1)
                                            .monospacedDigit(c.kind != .text)
                                    }.width(min: c.width ?? 60)
                                }
                            }
                        }
                        Inspector(row: r.first { $0.id == selection }).frame(minWidth: 240, idealWidth: 300)
                    }
                }
            } else if let error {
                ContentUnavailableView("Couldn't load \(config.title)", systemImage: "exclamationmark.triangle", description: Text(error))
            } else { ProgressView().controlSize(.large) }
        }
        .navigationTitle(config.title)
        .navigationSubtitle(config.endpoint)
        .searchable(text: $query, prompt: "Filter")
        .toolbar {
            if config.liveEvery != nil { Toggle("Live", systemImage: "dot.radiowaves.left.and.right", isOn: $live) }
            Button("Refresh", systemImage: "arrow.clockwise") { Task { await load() } }.disabled(loading)
        }
        .task(id: config.endpoint) { await load() }
        .task(id: live) {
            guard live, let every = config.liveEvery else { return }
            while !Task.isCancelled { try? await Task.sleep(for: .seconds(every)); if Task.isCancelled { break }; await load() }
        }
    }

    private func load() async {
        guard let c = model.client else { return }
        loading = true; defer { loading = false }
        do {
            var req = c.request("GET", config.endpoint, query: config.query)
            req.timeoutInterval = 20
            value = try JSONDecoder().decode(JSONValue.self, from: await c.send(req)); error = nil
        } catch NetraError.http(let s, let m) { error = "HTTP \(s): \(m)"; if value == nil { value = nil } }
        catch { self.error = error.localizedDescription }
    }
}

extension DataPageView where Header == EmptyView {
    init(_ config: PageConfig) { self.init(config, header: { _ in EmptyView() }) }
}

struct ColumnComparator: SortComparator, Hashable {
    var path: String
    var kind: CellKind
    var order: SortOrder = .forward
    func compare(_ l: ControlRow, _ r: ControlRow) -> ComparisonResult {
        let a = l.value.at(path), b = r.value.at(path)
        let cmp: ComparisonResult = CellFormat.less(a, b, kind) ? .orderedAscending : CellFormat.less(b, a, kind) ? .orderedDescending : .orderedSame
        return order == .forward ? cmp : (cmp == .orderedAscending ? .orderedDescending : cmp == .orderedDescending ? .orderedAscending : .orderedSame)
    }
}

struct StatRow: View {
    let stats: [PageStat]
    let value: JSONValue
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 10) { ForEach(stats) { s in StatCard(title: s.title, value: s.value(value), symbol: s.symbol, tint: s.tint) } }
        }.padding(.bottom, 8)
    }
}

struct StatCard: View {
    let title: String
    let value: String
    var symbol: String? = nil
    var tint: Color = .accentColor
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 5) {
                if let symbol { Image(systemName: symbol).foregroundStyle(tint) }
                Text(title).font(.caption).foregroundStyle(.secondary)
            }
            Text(value.isEmpty ? "–" : value).font(.title2.weight(.semibold)).monospacedDigit().lineLimit(1)
        }
        .padding(10).frame(minWidth: 120, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
    }
}

/// Label/value list for single-object pages (health, scorecard, SLO…).
struct KVSection: View {
    let title: String
    let items: [(label: String, value: String)]
    var body: some View {
        GroupBox(title) {
            VStack(spacing: 6) {
                ForEach(Array(items.enumerated()), id: \.offset) { _, kv in
                    HStack(alignment: .firstTextBaseline) {
                        Text(kv.label).foregroundStyle(.secondary); Spacer()
                        Text(kv.value.isEmpty ? "–" : kv.value).monospacedDigit().textSelection(.enabled).multilineTextAlignment(.trailing)
                    }
                }
            }.frame(maxWidth: .infinity)
        }
    }
}

private struct Inspector: View {
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

private extension View {
    func monospacedDigit(_ on: Bool) -> some View { on ? AnyView(self.monospacedDigit()) : AnyView(self) }
}
