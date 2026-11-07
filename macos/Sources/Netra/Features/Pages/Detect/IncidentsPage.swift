// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// Cross-signal incident clusters (GET api/v1/incidents) and the audit/health timeline
/// (GET api/v1/incidents/timeline). Read-only.
struct IncidentsPage: View {
    enum Mode: String, CaseIterable, Identifiable { case clusters = "Incidents", timeline = "Timeline"; var id: String { rawValue } }
    @State private var mode = Mode.clusters

    var body: some View {
        VStack(spacing: 0) {
            Picker("View", selection: $mode) { ForEach(Mode.allCases) { Text($0.rawValue).tag($0) } }
                .pickerStyle(.segmented).labelsHidden().frame(maxWidth: 260).padding(8)
            switch mode {
            case .clusters: IncidentClustersView()
            case .timeline: IncidentTimelineView()
            }
        }
    }
}

private struct IncidentClustersView: View {
    @State private var selection: String?
    @State private var query = ""

    var body: some View {
        JSONLoader(title: "Incidents", path: "api/v1/incidents") { json in
            let all = DetectData.incidents(json)
            let list = query.isEmpty ? all : all.filter { $0.subject.localizedCaseInsensitiveContains(query) || $0.sourceKey.localizedCaseInsensitiveContains(query) || $0.kinds.joined(separator: " ").localizedCaseInsensitiveContains(query) }
            VStack(spacing: 0) {
                HStack {
                    StatCard(title: "Incidents", value: "\(all.count)", symbol: "exclamationmark.triangle")
                    StatCard(title: "Critical / high", value: "\(all.filter { DetectData.severityRank($0.severity) >= 3 }.count)", symbol: "flame", tint: .red)
                    StatCard(title: "Findings", value: "\(all.reduce(0) { $0 + $1.findings.count })", symbol: "list.bullet")
                    Spacer()
                }.padding([.horizontal, .top])
                if list.isEmpty {
                    ContentUnavailableView(all.isEmpty ? "No correlated incidents" : "No matches", systemImage: "checkmark.shield",
                        description: Text(all.isEmpty ? "An incident needs findings from at least two different signals on the same source." : "Try a different filter."))
                } else {
                    HSplitView {
                        List(list, selection: $selection) { inc in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack { DetectSeverityBadge(severity: inc.severity); Spacer(); Text(fmtTime(inc.latest)).font(.caption).foregroundStyle(.secondary) }
                                Text(inc.subject).font(.headline).lineLimit(1)
                                Text("\(inc.findings.count) findings · \(inc.kinds.joined(separator: ", "))").font(.caption).foregroundStyle(.secondary)
                            }.padding(.vertical, 2).tag(inc.id)
                            .accessibilityElement(children: .combine)
                        }.frame(minWidth: 280, idealWidth: 340)
                        IncidentDetail(incident: list.first { $0.id == selection })
                            .frame(minWidth: 320)
                    }
                }
            }
        }
        .searchable(text: $query, prompt: "Filter incidents")
    }
}

private struct IncidentDetail: View {
    let incident: DetectData.Incident?
    var body: some View {
        if let incident {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    HStack { DetectSeverityBadge(severity: incident.severity); Text(incident.subject).font(.title3.weight(.semibold)) }
                    Text(incident.sourceKey).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                    Divider()
                    ForEach(Array(incident.findings.enumerated()), id: \.offset) { _, f in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 8) {
                                DetectSeverityBadge(severity: f.severity)
                                Text(f.kind).font(.caption.weight(.semibold)).padding(.horizontal, 6).padding(.vertical, 1).background(.quaternary, in: Capsule())
                                if !f.joinConfidence.isEmpty { Text("join: \(f.joinConfidence)").font(.caption).foregroundStyle(.secondary) }
                                Spacer(); Text(fmtTime(f.at)).font(.caption).foregroundStyle(.secondary)
                            }
                            if !f.subject.isEmpty { Text(f.subject).font(.callout.weight(.medium)) }
                            Text(f.message).font(.callout).textSelection(.enabled)
                        }
                        .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
                        .accessibilityElement(children: .combine)
                    }
                }.padding()
            }
        } else { ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select an incident to see its findings.")) }
    }
}

private struct IncidentTimelineView: View {
    private struct Bucket: Identifiable { let id = UUID(); let hour: Date; let kind: String; let count: Int }

    var body: some View {
        JSONLoader(title: "Incident timeline", path: "api/v1/incidents/timeline") { json in
            let tl = DetectData.timeline(json)
            VStack(spacing: 0) {
                HStack {
                    StatCard(title: "Entries", value: "\(tl.entries.count)", symbol: "clock")
                    StatCard(title: "Narration", value: tl.engine == "llm" ? "LLM rewrite" : "Heuristic", symbol: "text.alignleft")
                    Spacer()
                }.padding([.horizontal, .top])
                if tl.entries.isEmpty {
                    ContentUnavailableView("No timeline entries", systemImage: "clock", description: Text("Audit events and health transitions appear here."))
                } else {
                    if !tl.prose.isEmpty { GroupBox("Summary") { Text(tl.prose).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }.padding([.horizontal, .top]) }
                    let buckets = buckets(tl.entries)
                    Chart(buckets) { b in
                        BarMark(x: .value("Hour", b.hour, unit: .hour), y: .value("Entries", b.count)).foregroundStyle(by: .value("Kind", b.kind))
                    }.frame(height: 110).padding([.horizontal, .top])
                    .accessibilityLabel("Timeline entries per hour by kind")
                    List(tl.entries) { e in
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Text(e.at.map { $0.formatted(date: .abbreviated, time: .standard) } ?? "–").font(.caption.monospacedDigit()).foregroundStyle(.secondary).frame(width: 150, alignment: .leading)
                            if !e.severity.isEmpty { DetectSeverityBadge(severity: e.severity) }
                            Text(e.kind).font(.caption.weight(.semibold)).padding(.horizontal, 6).background(.quaternary, in: Capsule())
                            Text(e.text).textSelection(.enabled)
                        }.accessibilityElement(children: .combine)
                    }
                }
            }
        }
    }

    private func buckets(_ entries: [DetectData.TimelineItem]) -> [Bucket] {
        let cal = Calendar.current
        let g = Dictionary(grouping: entries.compactMap { e -> (Date, String)? in
            guard let at = e.at, let h = cal.dateInterval(of: .hour, for: at)?.start else { return nil }
            return (h, e.kind.isEmpty ? "other" : e.kind)
        }, by: { "\($0.0.timeIntervalSince1970)|\($0.1)" })
        return g.values.map { Bucket(hour: $0[0].0, kind: $0[0].1, count: $0.count) }
    }
}
