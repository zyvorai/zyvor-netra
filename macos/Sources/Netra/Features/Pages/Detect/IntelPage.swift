// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// Threat-intel hits, feed status/entries and revision history. Read-only: applying a feed
/// (a leased, risk-confirmed action) lives in the Enforcement page, never here.
struct IntelPage: View {
    enum Mode: String, CaseIterable, Identifiable { case hits = "Hits", feed = "Feed", history = "History"; var id: String { rawValue } }
    @State private var mode = Mode.hits

    var body: some View {
        VStack(spacing: 0) {
            Picker("View", selection: $mode) { ForEach(Mode.allCases) { Text($0.rawValue).tag($0) } }
                .pickerStyle(.segmented).labelsHidden().frame(maxWidth: 300).padding(8)
            switch mode {
            case .hits: IntelHitsView()
            case .feed: IntelFeedView()
            case .history: IntelHistoryView()
            }
        }
    }
}

private struct FeedCards: View {
    let feed: DetectData.FeedStatus
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 10) {
                StatCard(title: "Feed", value: feed.label, symbol: feed.label == "Active" ? "checkmark.seal" : "exclamationmark.triangle", tint: feed.label == "Active" ? .green : .orange)
                StatCard(title: "Entries", value: "\(feed.count)", symbol: "list.number")
                StatCard(title: "Revision", value: "\(feed.revision)", symbol: "number")
                StatCard(title: "Source", value: feed.source, symbol: "externaldrive.connected.to.line.below")
                StatCard(title: "Updated", value: fmtTime(feed.updatedAt), symbol: "clock")
                if feed.expiresAt != nil { StatCard(title: "Expires", value: fmtTime(feed.expiresAt), symbol: "hourglass", tint: feed.expired ? .red : .accentColor) }
                if feed.lastRefresh != nil { StatCard(title: "Last refresh", value: fmtTime(feed.lastRefresh), symbol: "arrow.triangle.2.circlepath") }
            }.padding([.horizontal, .top])
        }
    }
}

private struct FeedWarnings: View {
    let feed: DetectData.FeedStatus
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if !feed.refreshError.isEmpty { Label("Refresh error: \(feed.refreshError)", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
            if feed.journalUnavailable { Label("The intel journal is unavailable; the feed cannot be updated until it is repaired.", systemImage: "exclamationmark.octagon.fill").foregroundStyle(.red) }
            if !feed.persistent && feed.count > 0 { Label("Feed is held in memory only (not persisted).", systemImage: "memorychip").foregroundStyle(.secondary) }
        }.font(.caption).padding(.horizontal).frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct IntelHitsView: View {
    @State private var sort = [KeyPathComparator(\DetectData.IntelHit.packets, order: .reverse)]
    @State private var selection: Int?
    @State private var query = ""

    var body: some View {
        JSONLoader(title: "Intel hits", path: "api/v1/intel/hits") { json in
            let feed = DetectData.feedStatus(json), res = DetectData.intelHits(json)
            let rows = (query.isEmpty ? res.hits : res.hits.filter {
                [$0.value, $0.type, $0.workload, $0.node, $0.kind].contains { $0.localizedCaseInsensitiveContains(query) }
            }).sorted(using: sort)
            VStack(alignment: .leading, spacing: 8) {
                FeedCards(feed: feed)
                HStack(spacing: 10) {
                    StatCard(title: "Hits", value: "\(res.hits.count)", symbol: "eye.trianglebadge.exclamationmark", tint: res.hits.isEmpty ? .green : .red)
                    StatCard(title: "Entries checked", value: "\(res.checked)", symbol: "checklist")
                    StatCard(title: "Packets", value: "\(Int(res.totalPackets))", symbol: "shippingbox")
                    StatCard(title: "Blocked", value: "\(Int(res.totalBlocked))", symbol: "hand.raised")
                    if !res.byType.isEmpty {
                        Chart(res.byType, id: \.type) { BarMark(x: .value("Hits", $0.count), y: .value("Type", $0.type.isEmpty ? "?" : $0.type)) }
                            .frame(width: 180, height: 60).accessibilityLabel("Hits by indicator type")
                    }
                    Spacer()
                }.padding(.horizontal)
                FeedWarnings(feed: feed)
                if res.capped { Label("Results capped; narrow the feed to see everything.", systemImage: "scissors").font(.caption).padding(.horizontal) }
                if rows.isEmpty {
                    ContentUnavailableView(res.hits.isEmpty ? (feed.empty ? "No active feed" : "No hits") : "No matches", systemImage: res.hits.isEmpty ? "checkmark.shield" : "magnifyingglass",
                        description: Text(res.hits.isEmpty ? (res.note.isEmpty ? "Live traffic does not match the active feed." : res.note) : "Try a different filter."))
                } else {
                    Table(rows, selection: $selection, sortOrder: $sort) {
                        TableColumn("Indicator", value: \.value) { Text($0.value).textSelection(.enabled) }.width(min: 140)
                        TableColumn("Type", value: \.type) { Text($0.type) }.width(60)
                        TableColumn("Seen as", value: \.kind) { Text($0.kind) }.width(80)
                        TableColumn("Workload", value: \.workload) { Text($0.workload).lineLimit(1) }
                        TableColumn("Node", value: \.node) { Text($0.node) }
                        TableColumn("Packets", value: \.packets) { Text("\(Int($0.packets))").monospacedDigit() }.width(80)
                        TableColumn("Blocked", value: \.blocked) { Text("\(Int($0.blocked))").monospacedDigit() }.width(80)
                    }
                }
            }
        }
        .searchable(text: $query, prompt: "Filter hits")
    }
}

private struct IntelFeedView: View {
    @State private var query = ""
    var body: some View {
        JSONLoader(title: "Intel feed", path: "api/v1/intel/feed") { json in
            let feed = DetectData.feedStatus(json)
            let all = DetectData.feedEntries(json)
            let rows = query.isEmpty ? all : all.filter { $0.value.localizedCaseInsensitiveContains(query) || $0.type.localizedCaseInsensitiveContains(query) }
            VStack(alignment: .leading, spacing: 8) {
                FeedCards(feed: feed)
                if !feed.note.isEmpty { Label(feed.note, systemImage: "note.text").font(.caption).foregroundStyle(.secondary).padding(.horizontal) }
                FeedWarnings(feed: feed)
                if rows.isEmpty {
                    ContentUnavailableView(all.isEmpty ? "No active feed" : "No matches", systemImage: "tray", description: Text(all.isEmpty ? "Load a feed from the CLI or API to populate this list." : "Try a different filter."))
                } else {
                    Table(rows) {
                        TableColumn("Indicator") { Text($0.value).textSelection(.enabled) }.width(min: 160)
                        TableColumn("Type") { Text($0.type) }.width(70)
                        TableColumn("Direction") { Text($0.direction.isEmpty ? "any" : $0.direction) }.width(80)
                    }
                }
            }
        }
        .searchable(text: $query, prompt: "Filter entries")
    }
}

private struct IntelHistoryView: View {
    var body: some View {
        JSONLoader(title: "Intel history", path: "api/v1/intel/history", liveEvery: nil) { json in
            let feed = DetectData.feedStatus(json)
            let revs = DetectData.revisions(json)
            VStack(alignment: .leading, spacing: 8) {
                FeedCards(feed: feed)
                if !revs.isEmpty {
                    Chart(revs.reversed()) { r in
                        LineMark(x: .value("Revision", r.revision), y: .value("Entries", r.entries))
                        PointMark(x: .value("Revision", r.revision), y: .value("Entries", r.entries))
                    }.frame(height: 100).padding(.horizontal).accessibilityLabel("Entries per feed revision")
                }
                if revs.isEmpty {
                    ContentUnavailableView("No revisions", systemImage: "clock.arrow.circlepath", description: Text("Each feed update is recorded as a revision."))
                } else {
                    Table(revs) {
                        TableColumn("Rev") { Text("\($0.revision)\($0.revision == feed.revision ? "  (current)" : "")").monospacedDigit() }.width(min: 90)
                        TableColumn("Updated") { Text(fmtTime($0.updatedAt)) }.width(100)
                        TableColumn("Source") { Text($0.source) }
                        TableColumn("Entries") { Text("\($0.entries)").monospacedDigit() }.width(70)
                        TableColumn("Mix") { Text($0.byType.sorted { $0.key < $1.key }.map { "\($0.key) \($0.value)" }.joined(separator: ", ")) }
                        TableColumn("Expires") { Text($0.expiresAt == nil ? "" : fmtTime($0.expiresAt)) }.width(100)
                        TableColumn("Note") { Text($0.note) }
                    }
                }
            }
        }
    }
}
