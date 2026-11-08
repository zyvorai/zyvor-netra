// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Pure mapping for the AI pages (brief, digest, suggestions, ask, draft) and the fleet page.
/// Shapes mirror internal/ai (types.go, digest.go, draft.go, agent.go) and internal/fleet.
/// Everything is decoded schema-lessly; missing fields yield empty values, never a crash.
public enum AskData {
    /// Exact body for POST /api/v1/ai/ask and /ai/draft (the server uses strict field names).
    /// Omits conversationId when nil so the call stays stateless.
    public static func askBody(question: String, conversationID: String? = nil) -> Data {
        var o: [String: Any] = ["question": question.trimmingCharacters(in: .whitespacesAndNewlines)]
        if let c = conversationID, !c.isEmpty { o["conversationId"] = c }
        return (try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys])) ?? Data("{}".utf8)
    }

    /// Exact body for POST /api/v1/ai/explain (ai.ExplainRequest). Empty fields are omitted.
    public static func explainBody(kind: String, subject: String = "", message: String = "", severity: String = "", page: String = "", question: String = "") -> Data {
        var o: [String: Any] = ["kind": kind]
        for (k, v) in [("subject", subject), ("message", message), ("severity", severity), ("page", page), ("question", question)] where !v.isEmpty { o[k] = v }
        return (try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys])) ?? Data("{}".utf8)
    }

    // MARK: Agent (POST /api/v1/ai/agent)

    public struct AgentStep: Equatable, Sendable, Identifiable {
        public var node: String, detail: String
        public var id: String { "\(node)|\(detail)" }
    }
    /// ai.AgentResult: {brief, intent, draft?, suggestions?, steps:[{node,detail}], engine, conversationId}.
    /// The draft is a text preview only; nothing here can apply it.
    public struct AgentResult: Equatable, Sendable {
        public var brief: Brief
        public var intent: String, engine: String, conversationID: String
        public var steps: [AgentStep]
        public var suggestions: [String]
        public var draft: Draft?
        /// Tool/step trace as plain read-only text, one "n. node: detail" line per step.
        public var traceText: String {
            steps.enumerated().map { "\($0.offset + 1). \($0.element.node)" + ($0.element.detail.isEmpty ? "" : ": \($0.element.detail)") }.joined(separator: "\n")
        }
    }
    public static func agentResult(_ v: JSONValue) -> AgentResult {
        var steps: [AgentStep] = []
        if case .array(let a)? = v.at("steps") { steps = a.map { AgentStep(node: str($0, "node"), detail: str($0, "detail")) } }
        var d: Draft?
        if let dv = v.at("draft"), dv != .null { d = draft(dv) }
        return AgentResult(brief: brief(v.at("brief") ?? .null), intent: str(v, "intent"), engine: str(v, "engine"),
                           conversationID: str(v, "conversationId"), steps: steps, suggestions: strings(v.at("suggestions")), draft: d)
    }

    // MARK: Status

    public struct Status: Equatable, Sendable {
        public var enabled: Bool, heuristicOnly: Bool
        public var provider: String, model: String, mutations: String
        public var label: String { enabled ? "LLM rewrite on" + (model.isEmpty ? "" : " (\(model))") : "Heuristic only" }
    }
    public static func status(_ v: JSONValue) -> Status {
        Status(enabled: bool(v, "enabled"), heuristicOnly: bool(v, "heuristicOnly"),
               provider: str(v, "provider"), model: str(v, "model"), mutations: str(v, "mutations"))
    }

    // MARK: Findings and briefs

    public struct Finding: Equatable, Sendable, Identifiable {
        public var severity: String, kind: String, subject: String, message: String
        public var id: String { "\(kind)|\(subject)|\(message)" }
        /// NavSection raw value this finding belongs to, when known.
        public var sectionID: String? { AskData.sectionID(forKind: kind) }
    }
    public static func findings(_ v: JSONValue?) -> [Finding] {
        guard case .array(let a)? = v else { return [] }
        return a.map { Finding(severity: str($0, "severity"), kind: str($0, "kind"), subject: str($0, "subject"), message: str($0, "message")) }
    }

    public struct Brief: Equatable, Sendable {
        public var headline: String, severity: String, summary: String
        public var engine: String, model: String, question: String, conversationID: String
        public var findings: [Finding], nextSteps: [String]
        /// Raised metric alerts and anomalous metrics the brief cites (snapshot.metrics).
        public var metrics: [Finding]
        public var generatedAt: Date?
        public var healthScore: Int?, agentsTotal: Int, agentsStale: Int, mode: String
        public var isEmpty: Bool { headline.isEmpty && summary.isEmpty }
        /// Every cited item: findings, then drift/exposure/metrics from the snapshot, de-duplicated.
        public var citations: [Finding] = []
    }
    public static func brief(_ v: JSONValue) -> Brief {
        let snap = v.at("snapshot") ?? .null
        let metrics = findings(snap.at("metrics"))
        let f = findings(v.at("findings"))
        var seen = Set<String>(), cites: [Finding] = []
        for c in f + metrics + findings(snap.at("exposure")) + findings(snap.at("drift")) where seen.insert(c.id).inserted { cites.append(c) }
        return Brief(headline: str(v, "headline"), severity: str(v, "severity"), summary: str(v, "summary"),
                     engine: str(v, "engine"), model: str(v, "model"), question: str(v, "question"),
                     conversationID: str(v, "conversationId"),
                     findings: f, nextSteps: strings(v.at("nextSteps")), metrics: metrics,
                     generatedAt: CellFormat.date(v.at("generatedAt")),
                     healthScore: snap.at("healthScore").flatMap { $0.asDouble }.map { Int($0) },
                     agentsTotal: Int(snap.at("agentsTotal")?.asDouble ?? 0), agentsStale: Int(snap.at("agentsStale")?.asDouble ?? 0),
                     mode: str(snap, "mode"), citations: cites)
    }

    public struct Digest: Equatable, Sendable {
        public var headline: String, severity: String, card: String, previous: String
        public var changed: Bool
        public var suggestions: [String], whyChanged: [String]
        public var whyChangedProse: String
        public var brief: Brief
    }
    public static func digest(_ v: JSONValue) -> Digest {
        Digest(headline: str(v, "headline"), severity: str(v, "severity"), card: str(v, "card"),
               previous: str(v, "previousFingerprint"), changed: bool(v, "changed"),
               suggestions: strings(v.at("suggestions")), whyChanged: strings(v.at("whyChanged")),
               whyChangedProse: str(v, "whyChangedProse"), brief: brief(v.at("brief") ?? .null))
    }

    /// /ai/suggestions returns {"items": ["question", ...]}.
    public static func suggestions(_ v: JSONValue) -> [String] { strings(v.at("items")) }

    // MARK: Draft (text only)

    public struct Draft: Equatable, Sendable {
        public var understood: Bool
        public var confidence: String, kind: String, summary: String, applyMethod: String, applyPath: String, cli: String, note: String
        public var warnings: [String]
        /// Pretty-printed request body the draft proposes. Display only: the app never sends it.
        public var bodyText: String
        /// Everything as one copyable block of plain text.
        public var copyText: String
    }
    public static func draft(_ v: JSONValue) -> Draft {
        var body = ""
        if let b = v.at("body"), b != .null {
            let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]
            body = (try? e.encode(b)).map { String(decoding: $0, as: UTF8.self) } ?? ""
        }
        var d = Draft(understood: bool(v, "understood"), confidence: str(v, "confidence"), kind: str(v, "kind"),
                      summary: str(v, "summary"), applyMethod: str(v, "applyMethod"), applyPath: str(v, "applyPath"),
                      cli: str(v, "cli"), note: str(v, "note"), warnings: strings(v.at("warnings")), bodyText: body, copyText: "")
        var lines = [d.summary]
        if !d.cli.isEmpty { lines += ["", "CLI:", d.cli] }
        if !d.applyPath.isEmpty { lines += ["", "Endpoint: \(d.applyMethod) \(d.applyPath)"] }
        if !body.isEmpty { lines += ["", body] }
        lines += d.warnings.map { "Warning: \($0)" }
        d.copyText = lines.joined(separator: "\n")
        return d
    }

    // MARK: Citations

    /// Maps a finding kind to the NavSection raw value that shows it; nil when no page fits.
    public static func sectionID(forKind kind: String) -> String? {
        let k = kind.lowercased()
        if k == "metric-alert" { return "alerts" }
        if k == "metric-anomaly" { return "anomalies" }
        if k.hasPrefix("dns") { return "dns" }
        if k.hasPrefix("tcp") || k.hasPrefix("connect") || k == "connection-fanout" { return "flows" }
        if k.hasPrefix("icmp") || k.hasPrefix("kernel-network") || k.hasPrefix("bpf") { return "diagnostics" }
        if k == "exposure" || k == "drift" || k == "correlated-degradation" { return "insights" }
        if k.hasPrefix("fleet") { return "fleet" }
        return nil
    }

    /// Severity rank for sorting (critical first).
    public static func severityRank(_ s: String) -> Int {
        switch s.lowercased() { case "critical": 0; case "high": 1; case "warning", "medium": 2; case "info", "low": 3; default: 4 }
    }

    // MARK: Fleet

    public struct FleetSummary: Equatable, Sendable {
        public var nodes: Int, stale: Int, workloads: Int
        public var generatedAt: Date?
        public var healthyFraction: Double { nodes == 0 ? 0 : Double(nodes - stale) / Double(nodes) }
    }
    /// /api/v1/fleet: {generatedAt, nodes:[...], agentCount, staleAgents, workloads}.
    public static func fleetSummary(_ v: JSONValue) -> FleetSummary {
        FleetSummary(nodes: Int(v.at("agentCount")?.asDouble ?? Double(v.rows(at: "nodes").count)),
                     stale: Int(v.at("staleAgents")?.asDouble ?? 0), workloads: Int(v.at("workloads")?.asDouble ?? 0),
                     generatedAt: CellFormat.date(v.at("generatedAt")))
    }
    /// Health label for a node row: stale agents are "stale", otherwise "ok"; attached < programs is "degraded".
    public static func nodeHealth(_ row: JSONValue) -> String {
        if case .bool(true)? = row.at("stale") { return "stale" }
        let p = row.at("programs")?.asDouble ?? 0, a = row.at("attached")?.asDouble ?? 0
        return p > 0 && a < p ? "degraded" : "ok"
    }
    /// Clusters from /api/v1/fleet/clusters: {clusters:[{name,ok,local,tenant,agentCount,staleAgents,error,...}]}.
    public static func clusterHealth(_ row: JSONValue) -> String {
        if case .bool(false)? = row.at("ok") { return "unreachable" }
        return (row.at("staleAgents")?.asDouble ?? 0) > 0 ? "stale agents" : "ok"
    }

    // MARK: Helpers

    static func str(_ v: JSONValue, _ k: String) -> String { v[k]?.string ?? "" }
    static func bool(_ v: JSONValue, _ k: String) -> Bool { if case .bool(let b)? = v[k] { b } else { false } }
    static func strings(_ v: JSONValue?) -> [String] {
        guard case .array(let a)? = v else { return [] }
        return a.compactMap { $0.string }
    }
}
