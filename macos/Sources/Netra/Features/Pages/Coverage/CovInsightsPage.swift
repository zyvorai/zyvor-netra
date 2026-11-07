// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Read-only insight views the Insights page does not cover: RED, traces, profiles, warning events, kernel notes,
/// rates, remediations, new-since-start, the captured baselines and policy review. Nothing here captures, clears or applies.
struct CovInsightsPage: View {
    enum Tab: String, CaseIterable, Identifiable {
        case red = "RED", traces = "Traces", profiles = "Kernel stacks", events = "Warning events", notes = "Kernel notes", rates = "Rates"
        case remediations = "Remediations", newSince = "New since start", baseline = "Baseline", rateBaseline = "Rate baseline", review = "Policy review"
        var id: String { rawValue }
    }
    @State private var tab = Tab.red

    var body: some View {
        VStack(spacing: 0) {
            CovTabBar(tab: $tab)
            content.id(tab)
        }
    }

    @ViewBuilder private var content: some View {
        switch tab {
        case .red: CovRED()
        case .traces: CovTraces()
        case .profiles: CovProfiles()
        case .events: CovWarningEvents()
        case .notes: CovKernelNotes()
        case .rates: CovRates()
        case .remediations: CovRemediations()
        case .newSince: CovNewSinceStart()
        case .baseline: CovBaselineTab(title: "Behavior baseline", endpoint: "api/v1/insights/baseline", rate: false)
        case .rateBaseline: CovBaselineTab(title: "Rate baseline", endpoint: "api/v1/insights/rate-baseline", rate: true)
        case .review: CovPolicyReview()
        }
    }
}

/// A duration choice sent as a Go duration string.
private struct CovWindowPicker: View {
    let label: String
    let options: [String]
    @Binding var value: String
    var body: some View {
        HStack {
            Picker(label, selection: $value) { ForEach(options, id: \.self) { Text($0).tag($0) } }.pickerStyle(.segmented).frame(maxWidth: 360)
            Spacer()
        }.padding(.horizontal).padding(.vertical, 6)
    }
}

// MARK: RED

private struct CovRED: View {
    @State private var window = "5m"
    var body: some View {
        VStack(spacing: 0) {
            CovWindowPicker(label: "Window", options: ["5m", "15m", "1h", "6h"], value: $window)
            CovLoader(title: "RED", endpoint: "api/v1/insights/red", query: [.init(name: "window", value: window)], liveEvery: 15) { json in
                CovRowsView(json: json, rows: json.rows(at: "rows", idKeys: ["workloadName", "pod", "node"]), stats: [
                    .init(title: "Workloads", symbol: "square.stack.3d.up") { String(CoverageData.int($0["count"])) },
                    .init(title: "Window", symbol: "timer") { $0["window"]?.summary ?? "" },
                    .init(title: "Errors", symbol: "exclamationmark.circle", tint: .red) { v in String(DetectData.rows(v, "rows").reduce(0) { $0 + CoverageData.int($1["errors"]) }) },
                ], columns: [
                    .init(title: "Namespace", path: "namespace"), .init(title: "Workload", path: "workloadName", width: 160), .init(title: "Pod", path: "pod", width: 160),
                    .init(title: "Node", path: "node"), .init(title: "Packets", path: "packets", kind: .int), .init(title: "Bytes", path: "bytes", kind: .bytes),
                    .init(title: "Rate /s", path: "ratePerSec", kind: .number(2)), .init(title: "Errors", path: "errors", kind: .int),
                    .init(title: "Error ratio", path: "errorRatio", kind: .ratio), .init(title: "SRTT (us)", path: "avgSrttUs", kind: .int),
                    .init(title: "DNS fail", path: "dnsFailures", kind: .int), .init(title: "HTTP", path: "httpRequests", kind: .int),
                    .init(title: "HTTP 5xx", path: "http5xx", kind: .int), .init(title: "Protocols", path: "appProtocols"),
                ], empty: "No flow history in this window.", notes: CoverageData.notes(json))
            }
        }
    }
}

// MARK: Traces

private struct CovTraces: View {
    @State private var since = "15m"
    var body: some View {
        VStack(spacing: 0) {
            CovWindowPicker(label: "Since", options: ["5m", "15m", "1h", "6h"], value: $since)
            CovLoader(title: "Traces", endpoint: "api/v1/insights/traces", query: [.init(name: "since", value: since)], liveEvery: 15) { json in
                let t = CoverageData.traceStats(json)
                CovRowsView(json: json, rows: json.rows(at: "spans", idKeys: ["spanId"]), stats: [
                    .init(title: "Traces", symbol: "point.topleft.down.to.point.bottomright.curvepath") { _ in String(t.traces) },
                    .init(title: "Spans", symbol: "line.3.horizontal") { _ in String(t.spans) },
                    .init(title: "Inferred", symbol: "questionmark.circle", tint: .orange) { _ in String(t.inferred) },
                ], columns: [
                    .init(title: "Trace", path: "traceId", width: 110), .init(title: "Span", path: "spanId", width: 90), .init(title: "Parent", path: "parentId", width: 90),
                    .init(title: "Name", path: "name", width: 180), .init(title: "Namespace", path: "namespace"), .init(title: "Pod", path: "pod", width: 150),
                    .init(title: "Peer", path: "peer", width: 130), .init(title: "Port", path: "port", kind: .int, width: 60), .init(title: "App", path: "appProtocol"),
                    .init(title: "Callee", path: "calleePod", width: 150), .init(title: "Packets", path: "packets", kind: .int),
                    .init(title: "Start", path: "start", kind: .time), .init(title: "Inferred", path: "inferred", kind: .bool, width: 70),
                ], empty: "No call chains in this window.", notes: CoverageData.notes(json))
            }
        }
    }
}

// MARK: Profiles, events, kernel notes

private struct CovProfiles: View {
    var body: some View {
        CovLoader(title: "Kernel stacks", endpoint: "api/v1/insights/profiles", liveEvery: 30) { json in
            CovRowsView(json: json, rows: json.rows(at: "samples", idKeys: ["pid"]), stats: [
                .init(title: "Samples", symbol: "waveform") { String(CoverageData.int($0["count"])) },
            ], columns: [
                .init(title: "Node", path: "node"), .init(title: "PID", path: "pid", kind: .int, width: 70), .init(title: "Comm", path: "comm", width: 140),
                .init(title: "Frames", path: "frames", kind: .int, width: 70), .init(title: "Wait channel", path: "wchan", width: 180), .init(title: "Folded stack", path: "folded", width: 360),
            ], empty: "No kernel stack samples on the latest agent tick.", notes: CoverageData.notes(json))
        }
    }
}

private struct CovWarningEvents: View {
    var body: some View {
        CovLoader(title: "Warning events", endpoint: "api/v1/insights/workload-events", liveEvery: 30) { json in
            VStack(spacing: 0) {
                if !CoverageData.bool(json["available"]) {
                    Label(json["error"]?.string.map { "Events unavailable: \($0)" } ?? "Kubernetes events are unavailable (no cluster access).", systemImage: "exclamationmark.triangle")
                        .font(.callout).foregroundStyle(.orange).padding(8).frame(maxWidth: .infinity, alignment: .leading)
                }
                CovRowsView(json: json, rows: json.rows(at: "events", idKeys: ["pod", "reason"]), stats: [
                    .init(title: "Events", symbol: "exclamationmark.bubble") { String(DetectData.rows($0, "events").count) },
                ], columns: [
                    .init(title: "Last seen", path: "lastSeen", kind: .time), .init(title: "Namespace", path: "namespace"), .init(title: "Pod", path: "pod", width: 180),
                    .init(title: "Reason", path: "reason", width: 120), .init(title: "Count", path: "count", kind: .int, width: 60), .init(title: "Message", path: "message", width: 360),
                    .init(title: "Omitted", path: "messageOmitted", kind: .bool, width: 70),
                ], empty: "No Warning events.", notes: CoverageData.notes(json))
            }
        }
    }
}

private struct CovKernelNotes: View {
    var body: some View {
        CovLoader(title: "Kernel notes", endpoint: "api/v1/insights/kernel-notes", liveEvery: 30) { json in
            CovRowsView(json: json, rows: json.rows(at: "notes", idKeys: ["node"]), stats: [
                .init(title: "Notes", symbol: "text.alignleft") { String(CoverageData.int($0["count"])) },
            ], columns: [.init(title: "Node", path: "node", width: 140), .init(title: "Kernel log line", path: "text", width: 640)],
               empty: "No kernel network or OOM log lines.", notes: CoverageData.notes(json))
        }
    }
}

// MARK: Rates

private struct CovRates: View {
    @State private var window = "5m"
    var body: some View {
        VStack(spacing: 0) {
            CovWindowPicker(label: "Window", options: ["1m", "5m", "15m", "1h"], value: $window)
            CovLoader(title: "Rates", endpoint: "api/v1/insights/rates", query: [.init(name: "window", value: window)], liveEvery: 15) { json in
                VStack(spacing: 0) {
                    if CoverageData.bool(json["warming"]) {
                        Label("Rate windows are still warming up; rates may be incomplete.", systemImage: "thermometer.medium")
                            .font(.callout).foregroundStyle(.secondary).padding(8).frame(maxWidth: .infinity, alignment: .leading)
                    }
                    CovRowsView(json: json, rows: json.rows(at: "metrics", idKeys: ["source"]), stats: [
                        .init(title: "Sources", symbol: "waveform.path.ecg") { String(DetectData.rows($0, "metrics").count) },
                        .init(title: "Requested window", symbol: "timer") { $0["requestedWindowSeconds"]?.asDouble.map(CellFormat.duration) ?? "" },
                    ], columns: [
                        .init(title: "Source", path: "source", width: 220), .init(title: "Samples", path: "samples", kind: .int, width: 70),
                        .init(title: "Packets /s", path: "packetsPerSecond", kind: .number(2)), .init(title: "Bytes /s", path: "bytesPerSecond", kind: .bytes),
                        .init(title: "Blocked /s", path: "blockedPerSecond", kind: .number(2)), .init(title: "Conns /s", path: "connectionsPerSecond", kind: .number(2)),
                        .init(title: "DNS /s", path: "dnsQueriesPerSecond", kind: .number(2)), .init(title: "DNS fail /s", path: "dnsFailuresPerSecond", kind: .number(2)),
                        .init(title: "TLS /s", path: "tlsHandshakesPerSecond", kind: .number(2)), .init(title: "HTTP /s", path: "httpRequestsPerSecond", kind: .number(2)),
                    ], empty: "No rate samples yet.")
                }
            }
        }
    }
}

// MARK: Remediations, new since start

private struct CovRemediations: View {
    var body: some View {
        CovLoader(title: "Remediations", endpoint: "api/v1/insights/remediations", liveEvery: 30) { json in
            VStack(spacing: 0) {
                Label("Proposals only. They are never applied from here (review required, auto-apply \(CoverageData.bool(json["autoApply"]) ? "on" : "off")).", systemImage: "hand.raised")
                    .font(.callout).foregroundStyle(.secondary).padding(8).frame(maxWidth: .infinity, alignment: .leading)
                CovRowsView(json: json, rows: json.rows(at: "items", idKeys: ["id"]), stats: [
                    .init(title: "Proposals", symbol: "wrench.and.screwdriver") { String(CoverageData.int($0["count"])) },
                ], columns: [
                    .init(title: "Severity", path: "severity", width: 80), .init(title: "Kind", path: "kind", width: 120), .init(title: "Source", path: "source", width: 200),
                    .init(title: "Title", path: "title", width: 280), .init(title: "Rationale", path: "rationale.0", width: 320),
                    .init(title: "Review required", path: "reviewRequired", kind: .bool),
                ], empty: "No remediation proposals.")
            }
        }
    }
}

private struct CovNewSinceStart: View {
    @State private var maxRestarts = 5
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Stepper("Ignore pods restarted more than \(maxRestarts) times (0 = no filter)", value: $maxRestarts, in: 0...50)
                Spacer()
            }.padding(.horizontal).padding(.vertical, 6)
            CovLoader(title: "New since start", endpoint: "api/v1/insights/new-since-start", query: [.init(name: "maxRestarts", value: String(maxRestarts))], liveEvery: 30) { json in
                CovRowsView(json: json, rows: json.rows(at: "findings", idKeys: ["source", "value"]), stats: [
                    .init(title: "Findings", symbol: "sparkle") { String(CoverageData.int($0["count"])) },
                    .init(title: "Max restarts", symbol: "arrow.clockwise") { String(CoverageData.int($0["maxRestarts"])) },
                ], columns: [
                    .init(title: "Severity", path: "severity", width: 80), .init(title: "Kind", path: "kind", width: 100), .init(title: "Source", path: "source", width: 200),
                    .init(title: "Value", path: "value", width: 160), .init(title: "Count", path: "count", kind: .int, width: 60), .init(title: "Message", path: "message", width: 360),
                ], empty: "Nothing new since start (needs a captured baseline).", notes: CoverageData.notes(json))
            }
        }
    }
}

// MARK: Baselines (read only)

private struct CovBaselineTab: View {
    let title: String
    let endpoint: String
    let rate: Bool
    var body: some View {
        CovLoader(title: title, endpoint: endpoint) { json in
            let info = CoverageData.baselineInfo(json)
            if !info.captured {
                ContentUnavailableView("No baseline captured", systemImage: "camera.metering.none",
                                       description: Text("Capture one from the Insights page or netractl; this view only reads."))
            } else {
                CovRowsView(json: json.at("baseline") ?? json, rows: (json.at("baseline") ?? json).rows(at: "entries", idKeys: ["source", "value", "metric"]), stats: [
                    .init(title: "Captured", symbol: "camera.metering.center.weighted") { _ in CellFormat.text(.string(info.capturedAt), .time) },
                    .init(title: "Entries", symbol: "list.number") { _ in String(info.entries) },
                    .init(title: "Schema", symbol: "number") { _ in String(info.schemaVersion) },
                ] + (rate ? [PageStat(title: "Window", symbol: "timer") { _ in CellFormat.duration(Double(info.windowSeconds)) }] : []),
                columns: rate ? [
                    .init(title: "Source", path: "source", width: 240), .init(title: "Metric", path: "metric", width: 160), .init(title: "Rate /s", path: "rate", kind: .number(3)),
                ] : [
                    .init(title: "Source", path: "source", width: 240), .init(title: "Kind", path: "kind", width: 110), .init(title: "Value", path: "value", width: 240),
                    .init(title: "Count", path: "count", kind: .int),
                ], empty: "The baseline has no entries.")
            }
        }
    }
}

// MARK: Policy review

/// Pick a current recommendation, then read its review: plan, blast radius, matching policies and history.
/// The proposed manifest is never rendered or applied here.
private struct CovPolicyReview: View {
    @Environment(AppModel.self) private var model
    @State private var recs: [CoverageData.Recommendation] = []
    @State private var picked = ""
    @State private var loadedList = false
    @State private var failure: CovFailure?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("Recommendation", selection: $picked) {
                    Text("Choose a recommendation").tag("")
                    ForEach(recs) { Text($0.label).tag($0.id) }
                }.frame(maxWidth: 460)
                Spacer()
            }.padding(8)
            Divider()
            if let failure {
                ContentUnavailableView(failure.featureOff ? "Recommendations are off" : "Couldn't load recommendations",
                                       systemImage: failure.featureOff ? "power.dotted" : "exclamationmark.triangle", description: Text(failure.text))
            } else if picked.isEmpty {
                ContentUnavailableView(loadedList && recs.isEmpty ? "No recommendations" : "Pick a recommendation", systemImage: "doc.text.magnifyingglass",
                                       description: Text("Shows what applying the recommended policy would change. Review only; nothing is applied."))
            } else {
                CovLoader(title: "Policy review", endpoint: "api/v1/insights/policy-review", query: [.init(name: "recommendationId", value: picked)]) { json in
                    CovReviewBody(json: json)
                }.id(picked)
            }
        }
        .task {
            guard let c = model.client, !loadedList else { return }
            switch await CovFetch.get(c, "api/v1/insights/recommendations", feature: "Recommendations") {
            case .success(let v): recs = CoverageData.recommendations(v); failure = nil
            case .failure(let f): failure = f
            }
            loadedList = true
        }
    }
}

private struct CovReviewBody: View {
    let json: JSONValue
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 10) {
                    StatCard(title: "Risk", value: json.at("plan.risk")?.string ?? "", symbol: "gauge.with.dots.needle.67percent")
                    StatCard(title: "Engine", value: json["engine"]?.string ?? "", symbol: "gearshape")
                    StatCard(title: "Matching policies", value: String(DetectData.rows(json, "matchingPolicies").count), symbol: "scroll")
                }
                if CoverageData.bool(json["ambiguousMatch"]) {
                    Label("More than one policy matches this workload; the plan is analysed against the first match only.", systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                }
                if let prose = json["prose"]?.string, !prose.isEmpty { GroupBox("Summary") { Text(prose).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) } }
                KVSection(title: "Plan", items: CoverageData.planItems(json))
                list("Changes", CoverageData.strings(json.at("plan.changes")))
                list("Warnings", CoverageData.strings(json.at("plan.warnings")))
                list("Added destinations", CoverageData.strings(json.at("plan.addedDestinations")))
                list("Removed destinations", CoverageData.strings(json.at("plan.removedDestinations")))
                list("Rationale", CoverageData.strings(json.at("recommendation.rationale")))
                GroupBox("Blast radius") {
                    CovTable(rows: json.rows(at: "blastRadius", idKeys: ["destination"]), columns: [
                        .init(title: "Destination", path: "destination", width: 220), .init(title: "Kind", path: "kind", width: 100),
                        .init(title: "Correlated", path: "correlated", kind: .bool, width: 80), .init(title: "Active traffic", path: "activeTraffic", kind: .bool),
                        .init(title: "Note", path: "note", width: 320),
                    ], empty: "No destinations to correlate.").frame(height: 220)
                }
                GroupBox("Matching policies") {
                    CovTable(rows: json.rows(at: "matchingPolicies", idKeys: ["name"]), columns: [
                        .init(title: "Namespace", path: "namespace"), .init(title: "Name", path: "name", width: 220), .init(title: "Lockdown", path: "lockdown", kind: .bool),
                    ], empty: "No existing policy matches.").frame(height: 160)
                }
                GroupBox("Policy history") {
                    CovTable(rows: DetectData.rows(json, "history").enumerated().map { i, r in
                        ControlRow(id: "\(i)", value: .object(["id": r["id"] ?? .null, "at": r["at"] ?? .null, "actor": r["actor"] ?? .null, "action": r["action"] ?? .null, "name": r["name"] ?? .null]))
                    }, columns: [
                        .init(title: "When", path: "at", kind: .time), .init(title: "Actor", path: "actor", width: 140), .init(title: "Action", path: "action", width: 100), .init(title: "Policy", path: "name", width: 200),
                    ], empty: "No recorded revisions.").frame(height: 180)
                }
            }.padding()
        }
    }

    @ViewBuilder private func list(_ title: String, _ items: [String]) -> some View {
        if !items.isEmpty {
            GroupBox(title) {
                VStack(alignment: .leading, spacing: 4) { ForEach(Array(items.enumerated()), id: \.offset) { _, s in Text(s).textSelection(.enabled) } }
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}
