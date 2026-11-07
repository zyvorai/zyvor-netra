// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

typealias WLevel = WorkloadData.Level

extension WorkloadData.Level {
    var tint: Color { [Color.green, .blue, .orange, .red][rawValue] }
    static func from(label: String) -> WLevel { allCases.first { $0.label == label } ?? .ok }
}

/// One table column. `sortPath` lets a badge column sort by a numeric rank instead of its text.
struct WCol: Identifiable {
    enum Style { case plain, level, lockedBadge }
    let title: String
    let path: String
    var kind: CellKind = .text
    var sortPath: String? = nil
    var style: Style = .plain
    var width: CGFloat = 70
    var id: String { path + title }
}

/// A labelled field in the inspector.
struct WField: Identifiable {
    let label: String
    let path: String
    var kind: CellKind = .text
    var id: String { label + path }
}

/// Loads one JSON document (possibly merged from several endpoints), handles connection/error/loading states,
/// the Live toggle, Refresh and the filter field. Read-only: only GETs are issued by the loaders passed in.
struct WLPage<Content: View>: View {
    let title: String
    let subtitle: String
    var liveEvery: Double? = 5
    let load: @Sendable (NetraClient) async throws -> JSONValue
    @ViewBuilder let content: (JSONValue, String) -> Content
    @Environment(AppModel.self) private var model
    @State private var value: JSONValue?
    @State private var error: String?
    @State private var loading = false
    @State private var live = false
    @State private var query = ""
    @State private var updated: Date?

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else if let value {
                VStack(spacing: 0) {
                    if let error {
                        Label("Showing the last good data: \(error)", systemImage: "exclamationmark.triangle")
                            .font(.caption).foregroundStyle(.orange).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal).padding(.top, 6)
                    }
                    content(value, query)
                }
            } else if let error {
                ContentUnavailableView("Couldn't load \(title)", systemImage: "exclamationmark.triangle", description: Text(error))
            } else { ProgressView().controlSize(.large) }
        }
        .navigationTitle(title)
        .navigationSubtitle(subtitle)
        .searchable(text: $query, prompt: "Filter")
        .toolbar {
            if let updated { Text("Updated \(updated, style: .time)").font(.caption).foregroundStyle(.secondary) }
            if liveEvery != nil { Toggle("Live", systemImage: "dot.radiowaves.left.and.right", isOn: $live).help("Refresh automatically") }
            Button("Refresh", systemImage: "arrow.clockwise") { Task { await refresh() } }.disabled(loading)
        }
        .task(id: title) { await refresh() }
        .task(id: live) {
            guard live, let every = liveEvery else { return }
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(every))
                if Task.isCancelled { break }
                await refresh()
            }
        }
    }

    private func refresh() async {
        guard let c = model.client else { return }
        loading = true; defer { loading = false }
        do { value = try await load(c); error = nil; updated = Date() }
        catch NetraError.http(let s, let m) { error = "HTTP \(s): \(m)" }
        catch { self.error = error.localizedDescription }
    }
}

/// GET + decode helper for loaders.
func wlGET(_ c: NetraClient, _ path: String, _ query: [URLQueryItem] = [], timeout: TimeInterval = 20) async throws -> JSONValue {
    var r = c.request("GET", path, query: query); r.timeoutInterval = timeout
    return try JSONDecoder().decode(JSONValue.self, from: await c.send(r))
}

/// Like `wlGET` but a failure becomes nil: for optional companion endpoints that must not blank the page.
func wlOptional(_ c: NetraClient, _ path: String, _ query: [URLQueryItem] = []) async -> JSONValue? {
    try? await wlGET(c, path, query)
}

/// Sortable, filterable table with a side inspector.
struct WLTable<Detail: View>: View {
    let rows: [ControlRow]
    let columns: [WCol]
    var query = ""
    var empty = "Nothing to show right now."
    @ViewBuilder let detail: (ControlRow) -> Detail
    @State private var sort: [ColumnComparator] = []
    @State private var selection: ControlRow.ID?

    private var shown: [ControlRow] {
        var r = rows
        if !query.isEmpty {
            r = r.filter { row in columns.contains { CellFormat.text(row.value.at($0.path), $0.kind).localizedCaseInsensitiveContains(query) } }
        }
        return r.sorted(using: sort)
    }

    var body: some View {
        let r = shown
        HSplitView {
            if r.isEmpty {
                ContentUnavailableView(query.isEmpty ? empty : "No matches", systemImage: "tray").frame(minWidth: 300)
            } else {
                Table(r, selection: $selection, sortOrder: $sort) {
                    TableColumnForEach(columns) { c in
                        TableColumn(c.title, sortUsing: ColumnComparator(path: c.sortPath ?? c.path, kind: c.sortPath == nil ? c.kind : .int)) { (row: ControlRow) in
                            WLCell(row: row, col: c)
                        }.width(min: c.width)
                    }
                }.frame(minWidth: 380)
            }
            Group {
                if let row = r.first(where: { $0.id == selection }) {
                    ScrollView { detail(row).padding().frame(maxWidth: .infinity, alignment: .leading) }
                } else {
                    ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select a row to inspect."))
                }
            }.frame(minWidth: 260, idealWidth: 320)
        }
    }
}

extension WLTable where Detail == RowInspector {
    init(rows: [ControlRow], columns: [WCol], query: String = "", empty: String = "Nothing to show right now.", fields: [WField], labelsPath: String? = nil) {
        self.init(rows: rows, columns: columns, query: query, empty: empty) { RowInspector(row: $0, fields: fields, labelsPath: labelsPath) }
    }
}

private struct WLCell: View {
    let row: ControlRow
    let col: WCol
    var body: some View {
        let text = CellFormat.text(row.value.at(col.path), col.kind)
        switch col.style {
        case .plain:
            Text(text).lineLimit(1).monospacedDigit(col.kind != .text)
        case .level:
            let l = WLevel.from(label: text)
            Label(text, systemImage: l.symbol).foregroundStyle(l.tint).lineLimit(1)
                .accessibilityLabel("\(col.title): \(text)")
        case .lockedBadge:
            if text.isEmpty { Text("") } else { LockedBadge() }
        }
    }
}

private extension View {
    func monospacedDigit(_ on: Bool) -> some View { on ? AnyView(self.monospacedDigit()) : AnyView(self) }
}

/// Shown wherever the API reports a workload/pod as locked down by a Netra lockdown policy.
struct LockedBadge: View {
    var body: some View {
        Label("Locked down", systemImage: "lock.fill").font(.caption.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(Color.red.opacity(0.15), in: Capsule()).foregroundStyle(.red)
            .accessibilityLabel("Locked down")
    }
}

/// Field list + labels + raw JSON for the selected row.
struct RowInspector: View {
    let row: ControlRow
    let fields: [WField]
    var labelsPath: String? = nil
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            KVSection(title: "Details", items: fields.map { (label: $0.label, value: CellFormat.text(row.value.at($0.path), $0.kind)) })
            if let labelsPath, !WorkloadData.labelPairs(row.value.at(labelsPath)).isEmpty {
                LabelsView(pairs: WorkloadData.labelPairs(row.value.at(labelsPath)))
            }
            RawJSON(value: row.value)
        }
    }
}

struct LabelsView: View {
    let pairs: [(key: String, value: String)]
    var title = "Labels"
    var body: some View {
        GroupBox(title) {
            VStack(alignment: .leading, spacing: 3) {
                ForEach(Array(pairs.enumerated()), id: \.offset) { _, p in
                    Text("\(p.key)=\(p.value)").font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct RawJSON: View {
    let value: JSONValue
    var body: some View {
        DisclosureGroup("Raw JSON") {
            Text(pretty).font(.system(.caption2, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    private var pretty: String {
        let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return (try? e.encode(value)).map { String(decoding: $0, as: UTF8.self) } ?? value.summary
    }
}

/// Horizontal bar chart card with a value label on every bar (so colour is never the only cue).
struct BarCard: View {
    let title: String
    let data: [(name: String, value: Double)]
    var tint: Color = .accentColor
    var unit: ((Double) -> String) = { String(Int($0.rounded())) }
    var body: some View {
        GroupBox(title) {
            if data.isEmpty {
                Text("No data yet").font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 60)
            } else {
                Chart(data, id: \.name) { d in
                    BarMark(x: .value("Count", d.value), y: .value("Name", d.name)).foregroundStyle(tint.gradient)
                        .annotation(position: .trailing) { Text(unit(d.value)).font(.caption2).monospacedDigit().foregroundStyle(.secondary) }
                }
                .chartXAxis(.hidden)
                .chartYAxis { AxisMarks { _ in AxisValueLabel().font(.caption2) } }
                .frame(height: CGFloat(max(data.count, 2)) * 22 + 10)
                .accessibilityLabel(title)
                .accessibilityValue(data.map { "\($0.name) \(unit($0.value))" }.joined(separator: ", "))
            }
        }
    }
}

/// Donut of a categorical split with a legend that repeats the numbers.
struct DonutCard: View {
    let title: String
    let data: [(name: String, value: Double, tint: Color)]
    var body: some View {
        GroupBox(title) {
            let total = data.reduce(0) { $0 + $1.value }
            if total <= 0 {
                Text("No data yet").font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 60)
            } else {
                HStack(spacing: 14) {
                    Chart(data.filter { $0.value > 0 }, id: \.name) { d in
                        SectorMark(angle: .value("Count", d.value), innerRadius: .ratio(0.6), angularInset: 1).foregroundStyle(d.tint)
                    }.frame(width: 90, height: 90)
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(data.filter { $0.value > 0 }, id: \.name) { d in
                            HStack(spacing: 5) {
                                Circle().fill(d.tint).frame(width: 8, height: 8)
                                Text("\(d.name): \(Int(d.value))").font(.caption).monospacedDigit()
                            }
                        }
                    }
                    Spacer(minLength: 0)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// Wraps a row of chart cards so they share the width.
struct ChartRow<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        HStack(alignment: .top, spacing: 10) { content }.padding([.horizontal, .bottom])
    }
}

/// Tab picker used by the multi-table pages.
struct WLTabs<T: Hashable & CaseIterable & RawRepresentable>: View where T.RawValue == String, T.AllCases: RandomAccessCollection {
    @Binding var selection: T
    var body: some View {
        Picker("View", selection: $selection) { ForEach(T.allCases, id: \.self) { Text($0.rawValue).tag($0) } }
            .pickerStyle(.segmented).labelsHidden().padding(.horizontal).padding(.bottom, 8)
    }
}
