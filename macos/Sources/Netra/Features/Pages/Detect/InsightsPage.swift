// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import Charts
import NetraKit

/// Multi-tab insights browser. One tab per insight family served by GET api/v1/insights/*. Read-only:
/// recommendations, drafts and playbooks are suggestions to review elsewhere, never applied from here.
struct InsightsPage: View {
    enum Tab: String, CaseIterable, Identifiable {
        case overview = "Overview", exposure = "Exposure", drift = "Drift", rateDrift = "Rate drift", dependencies = "Dependencies"
        case blast = "Blast radius", lateral = "Lateral", exfil = "Exfil", shadow = "Shadow SaaS", downgrades = "Downgrades"
        case zeroTrust = "Zero trust", recommendations = "Recommendations", packs = "Policy packs"
        var id: String { rawValue }
    }
    @State private var tab = Tab.overview

    var body: some View {
        VStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ForEach(Tab.allCases) { t in
                        Button(t.rawValue) { tab = t }
                            .buttonStyle(.bordered).controlSize(.small)
                            .tint(t == tab ? .accentColor : .secondary)
                            .accessibilityAddTraits(t == tab ? .isSelected : [])
                    }
                }.padding(8)
            }
            Divider()
            content.id(tab)
        }
    }

    @ViewBuilder private var content: some View {
        switch tab {
        case .overview: InsightsOverview()
        case .blast: BlastRadiusView()
        case .downgrades: DataPageView(Self.downgrades) { json in
            if case .bool(true)? = json["l7Degraded"] {
                Label("L7 visibility is degraded on \((json["l7DegradedNodes"].flatMap { v -> [String]? in if case .array(let a) = v { a.map(\.summary) } else { nil } } ?? []).joined(separator: ", ")). An empty list does not confirm there are no downgrades.", systemImage: "eye.slash")
                    .font(.callout).foregroundStyle(.orange).padding(.horizontal).padding(.bottom, 6).frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        case .exposure: DataPageView(Self.exposure) { SeverityHeader(json: $0, path: "items") }
        case .drift: DataPageView(Self.drift) { SeverityHeader(json: $0, path: "findings") }
        case .rateDrift: DataPageView(Self.rateDrift) { SeverityHeader(json: $0, path: "findings") }
        case .dependencies: DataPageView(Self.dependencies)
        case .lateral: DataPageView(Self.lateral) { SeverityHeader(json: $0, path: "playbooks") }
        case .exfil: DataPageView(Self.exfil) { SeverityHeader(json: $0, path: "findings") }
        case .shadow: DataPageView(Self.shadow)
        case .zeroTrust: DataPageView(Self.zeroTrust) { SeverityHeader(json: $0, path: "drafts") }
        case .recommendations: DataPageView(Self.recommendations)
        case .packs: DataPageView(Self.packs)
        }
    }

    // MARK: Table configs (field names from the Go structs in internal/models, internal/exfil, internal/shadowsaas, ...)

    static let exposure = PageConfig(title: "Exposure", endpoint: "api/v1/insights/exposure", rowsPath: "items", idKeys: ["source"], columns: [
        .init(title: "Severity", path: "severity", width: 80), .init(title: "Score", path: "score", kind: .int, width: 60),
        .init(title: "Source", path: "source", width: 200), .init(title: "External deps", path: "externalDependencies", kind: .int),
        .init(title: "Behavior drift", path: "behaviorDrift", kind: .int), .init(title: "Rate drift", path: "rateDrift", kind: .int),
        .init(title: "Reasons", path: "reasons")
    ], stats: [
        .init(title: "Sources scored", symbol: "scope") { String($0.rows(at: "items").count) },
        .init(title: "High / critical", symbol: "flame", tint: .red) { v in String(DetectData.rows(v, "items").filter { DetectData.severityRank($0["severity"]?.string) >= 3 }.count) }
    ], emptyText: "No exposure scored.")

    static let drift = PageConfig(title: "Behavior drift", endpoint: "api/v1/insights/drift", rowsPath: "findings", idKeys: ["source", "value"], columns: [
        .init(title: "Severity", path: "severity", width: 80), .init(title: "Kind", path: "kind", width: 100),
        .init(title: "Source", path: "source", width: 200), .init(title: "Value", path: "value", width: 160),
        .init(title: "Count", path: "count", kind: .int, width: 60), .init(title: "Message", path: "message")
    ], stats: [
        .init(title: "Findings", symbol: "arrow.triangle.branch") { String($0.rows(at: "findings").count) },
        .init(title: "Baseline", symbol: "camera.metering.center.weighted") { $0["baselineCapturedAt"].map { CellFormat.text($0, .time) } ?? "none captured" }
    ], emptyText: "No drift from the captured baseline (or no baseline captured).")

    static let rateDrift = PageConfig(title: "Rate drift", endpoint: "api/v1/insights/rate-drift", rowsPath: "findings", idKeys: ["source", "metric"], columns: [
        .init(title: "Severity", path: "severity", width: 80), .init(title: "Source", path: "source", width: 200), .init(title: "Metric", path: "metric", width: 120),
        .init(title: "Baseline /s", path: "baselineRate", kind: .number(2)), .init(title: "Current /s", path: "currentRate", kind: .number(2)),
        .init(title: "Ratio", path: "ratio", kind: .number(1)), .init(title: "Message", path: "message")
    ], stats: [
        .init(title: "Findings", symbol: "waveform.path.ecg") { String($0.rows(at: "findings").count) },
        .init(title: "Window", symbol: "timer") { v in DetectData.rateDriftWindowSeconds(v).map(CellFormat.duration) ?? "–" }
    ], emptyText: "No rate drift (the window may still be warming up).")

    static let dependencies = PageConfig(title: "Dependencies", endpoint: "api/v1/insights/dependencies", rowsPath: "edges", idKeys: ["source"], columns: [
        .init(title: "Source", path: "source", width: 200), .init(title: "Target", path: "target", width: 200), .init(title: "Proto", path: "protocol", width: 60),
        .init(title: "Port", path: "port", kind: .int, width: 60), .init(title: "Packets", path: "packets", kind: .int), .init(title: "Bytes", path: "bytes", kind: .bytes),
        .init(title: "Blocked", path: "blocked", kind: .int), .init(title: "External", path: "external", kind: .bool, width: 70)
    ], stats: [
        .init(title: "Edges", symbol: "point.3.connected.trianglepath.dotted") { String($0.rows(at: "edges").count) },
        .init(title: "Nodes", symbol: "circle.grid.cross") { String($0.rows(at: "nodes").count) },
        .init(title: "External edges", symbol: "globe", tint: .orange) { v in String(DetectData.rows(v, "edges").filter { if case .bool(true)? = $0["external"] { true } else { false } }.count) }
    ], emptyText: "No dependency edges observed.")

    static let lateral = PageConfig(title: "Lateral movement", endpoint: "api/v1/insights/lateral", rowsPath: "playbooks", columns: [
        .init(title: "Severity", path: "severity", width: 80), .init(title: "Finding", path: "findingType", width: 120), .init(title: "Namespace", path: "namespace"),
        .init(title: "Pod", path: "pod", width: 160), .init(title: "Node", path: "node"), .init(title: "Title", path: "title", width: 240)
    ], stats: [.init(title: "Playbooks", symbol: "figure.walk.motion") { String($0.rows(at: "playbooks").count) }],
       emptyText: "No lateral-movement findings. Needs the scan detector.")

    static let exfil = PageConfig(title: "Exfiltration signals", endpoint: "api/v1/insights/exfil", rowsPath: "findings", idKeys: ["pod", "workloadName"], columns: [
        .init(title: "Severity", path: "severity", width: 80), .init(title: "Score", path: "score", kind: .int, width: 60),
        .init(title: "Namespace", path: "namespace"), .init(title: "Workload", path: "workloadName", width: 160), .init(title: "Pod", path: "pod", width: 160),
        .init(title: "Unique dst", path: "uniqueDestinations", kind: .int), .init(title: "External dst", path: "externalDestinations", kind: .int),
        .init(title: "Bytes", path: "bytes", kind: .bytes), .init(title: "Signals", path: "signals"), .init(title: "Rationale", path: "rationale", width: 240)
    ], stats: [
        .init(title: "Findings", symbol: "arrow.up.right.circle") { String($0.rows(at: "findings").count) },
        .init(title: "High", symbol: "flame", tint: .red) { $0["high"]?.summary ?? "–" }
    ], emptyText: "No exfiltration signals.")

    static let shadow = PageConfig(title: "Shadow SaaS", endpoint: "api/v1/insights/shadow-saas", rowsPath: "findings", idKeys: ["host"], columns: [
        .init(title: "Risk", path: "risk", width: 70), .init(title: "Status", path: "status", width: 90), .init(title: "Host", path: "host", width: 220),
        .init(title: "Seen via", path: "kind", width: 80), .init(title: "Category", path: "category"), .init(title: "AI", path: "aiRelated", kind: .bool, width: 50),
        .init(title: "Namespace", path: "namespace"), .init(title: "Pod", path: "pod", width: 160), .init(title: "Packets", path: "packets", kind: .int)
    ], stats: [
        .init(title: "Shadow", symbol: "questionmark.app", tint: .red) { $0["shadow"]?.summary ?? "–" },
        .init(title: "Unknown", symbol: "questionmark.circle", tint: .orange) { $0["unknown"]?.summary ?? "–" },
        .init(title: "Sanctioned seen", symbol: "checkmark.seal", tint: .green) { $0["sanctionedSeen"]?.summary ?? "–" }
    ], emptyText: "No SaaS destinations observed.")

    static let downgrades = PageConfig(title: "Protocol downgrades", endpoint: "api/v1/insights/protocol-downgrades", rowsPath: "findings", idKeys: ["source", "host"], columns: [
        .init(title: "Severity", path: "severity", width: 80), .init(title: "Source", path: "source", width: 200), .init(title: "Host", path: "host", width: 200),
        .init(title: "TLS still active", path: "tlsStillActive", kind: .bool), .init(title: "Message", path: "message")
    ], stats: [.init(title: "Findings", symbol: "lock.open") { String($0.rows(at: "findings").count) }], emptyText: "No protocol downgrades observed.")

    static let zeroTrust = PageConfig(title: "Zero-trust drafts", endpoint: "api/v1/insights/zero-trust", rowsPath: "drafts", columns: [
        .init(title: "Severity", path: "severity", width: 80), .init(title: "Kind", path: "kind", width: 110), .init(title: "Namespace", path: "namespace"),
        .init(title: "Workload", path: "workloadName", width: 160), .init(title: "Title", path: "title", width: 260), .init(title: "Packets", path: "packets", kind: .int)
    ], stats: [.init(title: "Review-only drafts", symbol: "lock.shield") { String($0.rows(at: "drafts").count) }], emptyText: "No zero-trust drafts.")

    static let recommendations = PageConfig(title: "Policy recommendations", endpoint: "api/v1/insights/recommendations", rowsPath: "items", columns: [
        .init(title: "Confidence", path: "confidence", width: 90), .init(title: "Kind", path: "kind", width: 130), .init(title: "Namespace", path: "namespace"),
        .init(title: "Workload", path: "workloadName", width: 180), .init(title: "Rationale", path: "rationale.0", width: 320)
    ], stats: [
        .init(title: "Recommendations", symbol: "lightbulb") { String($0.rows(at: "items").count) },
        .init(title: "Cilium", symbol: "shield") { $0["ciliumEnabled"]?.summary ?? "–" }
    ], emptyText: "No recommendations. Review and apply happen outside this read-only view.")

    static let packs = PageConfig(title: "Policy packs", endpoint: "api/v1/insights/policy-packs", rowsPath: "packs", columns: [
        .init(title: "Namespace", path: "namespace"), .init(title: "Name", path: "name", width: 200), .init(title: "Pods", path: "podCount", kind: .int, width: 60),
        .init(title: "FQDNs", path: "fqdns", width: 280), .init(title: "Prefer PacketWolf", path: "preferPacketWolf", kind: .bool), .init(title: "Rationale", path: "rationale.0", width: 280)
    ], stats: [
        .init(title: "Packs", symbol: "shippingbox") { String($0.rows(at: "packs").count) },
        .init(title: "Sanctioned hosts", symbol: "checkmark.seal") { $0["sanctionedListSize"]?.summary ?? "–" }
    ], emptyText: "No policy packs (needs NETRA_SANCTIONED_HOSTS and observed traffic).")
}

/// Severity counts above a table, computed from the rows at `path`.
private struct SeverityHeader: View {
    let json: JSONValue
    let path: String
    var body: some View {
        let counts = DetectData.severityCounts(DetectData.rows(json, path))
        if !counts.isEmpty { SeverityBars(counts: counts).padding(.horizontal).padding(.bottom, 6) }
    }
}

private struct InsightsOverview: View {
    var body: some View {
        JSONLoader(title: "Insights", path: "api/v1/insights/summary") { s in
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: 10)], alignment: .leading, spacing: 10) {
                        stat("Dependency edges", s, "dependencyEdges", "point.3.connected.trianglepath.dotted")
                        stat("External edges", s, "externalEdges", "globe")
                        stat("Baseline entries", s, "baselineEntries", "camera.metering.center.weighted")
                        stat("Drift findings", s, "driftFindings", "arrow.triangle.branch")
                        stat("Rate drift", s, "rateDriftFindings", "waveform.path.ecg")
                        stat("High exposure", s, "highExposure", "flame")
                        stat("Recommendations", s, "recommendations", "lightbulb")
                        stat("Remediation proposals", s, "remediationProposals", "wrench.and.screwdriver")
                    }
                    if case .bool(true)? = s["rateWarming"] {
                        Label("Rate baselines are still warming up; rate drift may be incomplete.", systemImage: "thermometer.medium").font(.callout).foregroundStyle(.secondary)
                    }
                    HealthTrendCard()
                }.padding()
            }
        }
    }

    private func stat(_ title: String, _ s: JSONValue, _ key: String, _ symbol: String) -> some View {
        StatCard(title: title, value: s[key]?.asDouble.map { String(Int($0)) } ?? "", symbol: symbol)
    }
}

private struct HealthTrendCard: View {
    @Environment(AppModel.self) private var model
    @State private var trend: DetectData.HealthTrend?
    @State private var failed = false

    var body: some View {
        GroupBox("Health trend") {
            if let t = trend {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 24) {
                        VStack(alignment: .leading) { Text("Score").font(.caption).foregroundStyle(.secondary); Text("\(t.currentScore)").font(.largeTitle.weight(.semibold)).monospacedDigit() }
                        VStack(alignment: .leading) { Text("Trend").font(.caption).foregroundStyle(.secondary)
                            Label(String(format: "%+.1f / h", t.slopePerHour), systemImage: t.slopePerHour < 0 ? "arrow.down.right" : t.slopePerHour > 0 ? "arrow.up.right" : "arrow.right").monospacedDigit() }
                        VStack(alignment: .leading) { Text("Threshold \(t.threshold)").font(.caption).foregroundStyle(.secondary); Text(t.summary).foregroundStyle(t.timeToBreak == nil ? Color.secondary : .orange) }
                        VStack(alignment: .leading) { Text("Samples").font(.caption).foregroundStyle(.secondary); Text("\(t.samples)").monospacedDigit() }
                    }
                    Gauge(value: Double(min(max(t.currentScore, 0), 100)), in: 0...100) { Text("Score") }.tint(Gradient(colors: [.red, .yellow, .green]))
                    if !t.note.isEmpty { Text(t.note + (t.confidence.isEmpty ? "" : " Confidence: \(t.confidence).")).font(.caption).foregroundStyle(.secondary) }
                }.frame(maxWidth: .infinity, alignment: .leading)
            } else if failed { Text("Health trend unavailable.").foregroundStyle(.secondary) } else { ProgressView() }
        }
        .task {
            guard let c = model.client else { return }
            do { trend = DetectData.healthTrend(try await JSONDecoder().decode(JSONValue.self, from: c.send(c.request("GET", "api/v1/insights/health-trend")))) }
            catch { failed = true }
        }
    }
}

/// Blast radius needs a `root` (a dependency node id). Pick one from the live dependency graph.
private struct BlastRadiusView: View {
    @Environment(AppModel.self) private var model
    @State private var nodes: [String] = []
    @State private var root = ""
    @State private var hops = 3

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("Root", selection: $root) { Text("Choose a workload").tag(""); ForEach(nodes, id: \.self) { Text($0).tag($0) } }.frame(maxWidth: 420)
                Stepper("Hops: \(hops)", value: $hops, in: 1...6)
                Spacer()
            }.padding(8)
            if root.isEmpty {
                ContentUnavailableView("Pick a root", systemImage: "scope", description: Text("Shows everything reachable from a workload within N hops, to size the impact of an outage."))
            } else {
                DataPageView(PageConfig(title: "Blast radius", endpoint: "api/v1/insights/blast-radius",
                    query: [.init(name: "root", value: root), .init(name: "hops", value: String(hops))], rowsPath: "nodes", idKeys: ["id"], columns: [
                    .init(title: "Node", path: "id", width: 260), .init(title: "Hops", path: "hops", kind: .int, width: 60)
                ], stats: [
                    .init(title: "Reachable nodes", symbol: "circle.hexagongrid") { String($0.rows(at: "nodes").count) },
                    .init(title: "Edges", symbol: "arrow.left.arrow.right") { String($0.rows(at: "edges").count) },
                    .init(title: "Truncated", symbol: "scissors") { $0["truncated"]?.summary ?? "–" }
                ], emptyText: "Nothing reachable from this root.")) { json in
                    let h = DetectData.blastHops(json)
                    if !h.isEmpty {
                        Chart(h, id: \.hops) { BarMark(x: .value("Hops", String($0.hops)), y: .value("Nodes", $0.nodes)) }
                            .frame(height: 90).padding(.horizontal).accessibilityLabel("Reachable nodes by hop distance")
                    }
                }.id(root + String(hops))
            }
        }
        .task {
            guard let c = model.client else { return }
            if let v = try? await JSONDecoder().decode(JSONValue.self, from: c.send(c.request("GET", "api/v1/insights/dependencies", query: [.init(name: "limit", value: "1000")]))) {
                nodes = DetectData.rows(v, "nodes").compactMap { $0["id"]?.string }.sorted()
            }
        }
    }
}
