// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// Security review (GET api/v1/security/incidents): temporal correlation of independent evidence kinds
/// (dns, scan, intel) on the same node/namespace/pod. Read-only: it correlates and explains, nothing here
/// deletes a rule, applies a deny or quarantines.
struct SecurityPage: View {
    @State private var selection: String?
    @State private var query = ""

    var body: some View {
        JSONLoader(title: "Security review", path: "api/v1/security/incidents") { json in
            let review = DetectData.securityReview(json)
            let list = query.isEmpty ? review.incidents : review.incidents.filter {
                $0.workload.localizedCaseInsensitiveContains(query) || $0.node.localizedCaseInsensitiveContains(query)
                    || $0.evidence.contains { $0.message.localizedCaseInsensitiveContains(query) || $0.kind.localizedCaseInsensitiveContains(query) }
            }
            VStack(spacing: 0) {
                HStack(alignment: .top) {
                    StatCard(title: "Correlated incidents", value: "\(review.incidents.count)", symbol: "shield.lefthalf.filled")
                    StatCard(title: "Evidence items", value: "\(review.incidents.reduce(0) { $0 + $1.evidence.count })", symbol: "doc.text.magnifyingglass")
                    StatCard(title: "DNS detector", value: review.dnsEnabled ? "on" : "off", symbol: "network", tint: review.dnsEnabled ? .green : .secondary)
                    StatCard(title: "Scan detector", value: review.scanEnabled ? "on" : "off", symbol: "dot.radiowaves.left.and.right", tint: review.scanEnabled ? .green : .secondary)
                    if !review.evidenceByKind.isEmpty {
                        Chart(review.evidenceByKind, id: \.kind) { BarMark(x: .value("Count", $0.count), y: .value("Kind", $0.kind)) }
                            .frame(width: 200, height: 64).accessibilityLabel("Evidence count by kind")
                    }
                    Spacer()
                }.padding([.horizontal, .top])
                if !review.note.isEmpty || review.truncated {
                    Label(review.note + (review.truncated ? " Results were truncated." : ""), systemImage: "info.circle")
                        .font(.caption).foregroundStyle(.secondary).padding(.horizontal).padding(.top, 6).frame(maxWidth: .infinity, alignment: .leading)
                }
                if list.isEmpty {
                    ContentUnavailableView(review.incidents.isEmpty ? "No correlated security signals" : "No matches", systemImage: "checkmark.shield",
                        description: Text(review.incidents.isEmpty ? "Needs two different evidence kinds on the same pod within ten minutes." : "Try a different filter."))
                } else {
                    HSplitView {
                        List(list, selection: $selection) { inc in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack { DetectSeverityBadge(severity: inc.derivedSeverity); Spacer(); Text(fmtTime(inc.lastSeen)).font(.caption).foregroundStyle(.secondary) }
                                Text(inc.workload).font(.headline).lineLimit(1)
                                Text("\(inc.node) · \(inc.kinds.joined(separator: " + "))").font(.caption).foregroundStyle(.secondary)
                            }.tag(inc.id).accessibilityElement(children: .combine)
                        }.frame(minWidth: 280, idealWidth: 340)
                        Detail(incident: list.first { $0.id == selection }).frame(minWidth: 320)
                    }
                }
            }
        }
        .searchable(text: $query, prompt: "Filter by pod, node or evidence")
    }

    private struct Detail: View {
        let incident: DetectData.SecurityIncident?
        var body: some View {
            if let i = incident {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(i.workload).font(.title3.weight(.semibold))
                        Text("Node \(i.node) · last seen \(fmtTime(i.lastSeen))").font(.caption).foregroundStyle(.secondary)
                        Label("Severity is a display heuristic (3+ evidence kinds = high). The server does not rate these, and correlation does not prove causality.", systemImage: "info.circle")
                            .font(.caption).foregroundStyle(.secondary)
                        Divider()
                        Text("Evidence").font(.headline)
                        ForEach(i.evidence) { e in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text(e.kind).font(.caption.weight(.semibold)).padding(.horizontal, 6).padding(.vertical, 1).background(.quaternary, in: Capsule())
                                Text(e.message).textSelection(.enabled)
                                Spacer()
                                Text(e.at.map { $0.formatted(date: .omitted, time: .standard) } ?? "").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            }.accessibilityElement(children: .combine)
                        }
                    }.padding()
                }
            } else { ContentUnavailableView("No selection", systemImage: "sidebar.right", description: Text("Select an incident to see its evidence.")) }
        }
    }
}
