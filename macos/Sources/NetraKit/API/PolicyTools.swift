// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Policy and baseline tooling for routes the rest of the app never calls.
/// - Read-only computations (viewer role on the server): build, simulate, deny replay, watchlist match,
///   history export. These return a `URLRequest` (or a download) and never go through `MutationFlow`.
/// - Guarded changes: history import, AI-destination deny, baseline capture/clear. These are
///   `ControlAction`s, so they always preview first and send X-Netra-Confirm-Risk after a typed phrase when high.
public enum PolicyTools {

    // MARK: Read-only: build (POST /api/v1/policies/build): returns a manifest, never applies

    public static let buildFields: [FormField] = [
        .init("name", "Policy name"),
        .init("namespace", "Namespace", initial: "default"),
        .init("selector", "Pod selector", help: "key=value, comma separated. Required: the builder refuses namespace-wide selection"),
        .init("kind", "Destination kind", .choice(["fqdn", "cidr", "entity"]), initial: "fqdn"),
        .init("to", "Destinations", .multiline, help: "One per line or comma separated: names (fqdn), IPs/CIDRs (cidr) or entities"),
        .init("port", "Port", .number, help: "Optional, 1-65535"),
        .init("protocol", "Protocol", .choice(["TCP", "UDP", "ANY"]), initial: "TCP"),
        .init("includeDns", "Also allow DNS", .toggle, initial: "false"),
    ]

    public static func buildRequest(_ c: NetraClient, _ v: FormValues) -> Result<URLRequest, FormError> {
        let name = Form.str(v, "name")
        if name.isEmpty { return .failure(.init("A policy name is required")) }
        var scope = WorkloadScope(); scope.labels = Form.str(v, "selector")
        guard let selector = scope.labelMap else { return .failure(.init("Selector must look like key=value, key2=value2")) }
        if selector.isEmpty { return .failure(.init("A selector is required: namespace-wide selection is refused")) }
        let kind = Form.str(v, "kind").isEmpty ? "fqdn" : Form.str(v, "kind")
        guard ["fqdn", "cidr", "entity"].contains(kind) else { return .failure(.init("Kind must be fqdn, cidr or entity")) }
        let to = Form.list(v, "to")
        if to.isEmpty { return .failure(.init("At least one destination is required")) }
        if kind == "cidr", let bad = to.first(where: { !RuleDraft.isIP($0) && !RuleDraft.isCIDR($0) }) {
            return .failure(.init("\"\(bad)\" is not an IP or CIDR"))
        }
        var d: [String: Any] = ["name": name, "selector": selector, "kind": kind, "to": to]
        let ns = Form.str(v, "namespace"); if !ns.isEmpty { d["namespace"] = ns }
        if let p = Form.int(v, "port") {
            guard (1...65535).contains(p) else { return .failure(.init("Port must be 1-65535")) }
            d["port"] = p
        } else if !Form.str(v, "port").isEmpty { return .failure(.init("Port must be a number")) }
        let proto = Form.str(v, "protocol").uppercased()
        if !proto.isEmpty {
            guard ["TCP", "UDP", "ANY"].contains(proto) else { return .failure(.init("Protocol must be TCP, UDP or ANY")) }
            d["protocol"] = proto
        }
        if Form.flag(v, "includeDns") { d["includeDns"] = true }
        return .success(c.request("POST", "api/v1/policies/build", body: Form.json(d)))
    }

    // MARK: Read-only: simulate (POST /api/v1/policies/simulate): raw JSON CiliumNetworkPolicy body

    public static func simulateRequest(_ c: NetraClient, manifest: String) -> Result<URLRequest, FormError> {
        let raw = manifest.trimmingCharacters(in: .whitespacesAndNewlines)
        if raw.isEmpty { return .failure(.init("Paste a CiliumNetworkPolicy manifest (JSON)")) }
        guard raw.utf8.count <= 2 << 20 else { return .failure(.init("Manifest is larger than 2 MB")) }
        guard (try? JSONSerialization.jsonObject(with: Data(raw.utf8))) is [String: Any] else {
            return .failure(.init("The simulator needs a JSON object; YAML is not accepted"))
        }
        return .success(c.request("POST", "api/v1/policies/simulate", body: Data(raw.utf8)))
    }

    // MARK: Read-only: deny replay (POST /api/v1/ebpf/deny/preview-history)

    public static let denyHistoryFields: [FormField] = [
        .init("kind", "Kind", .choice(["ip", "cidr", "port", "dns", "sni"]), initial: "ip",
              help: "Process deny cannot be replayed against flow history"),
        .init("value", "Value", help: "IP, CIDR, port number, DNS name or SNI host"),
        .init("direction", "Direction", .choice(["", "both", "egress", "ingress"]), help: "Blank means both"),
        .init("protocol", "Protocol (port only)", .choice(["", "tcp", "udp", "any"])),
        .init("since", "Look back", initial: "1h", help: "A duration up to 168h, or an RFC3339 time in the last 7 days"),
        .init("namespace", "Namespace", help: "Optional workload filter"),
        .init("pod", "Pod"), .init("workloadKind", "Workload kind"), .init("workloadName", "Workload name"),
        .init("limit", "Max flows", .number, help: "Optional, default 2000"),
    ]

    public static func denyHistoryRequest(_ c: NetraClient, _ v: FormValues) -> Result<URLRequest, FormError> {
        let kind = Form.str(v, "kind"), value = Form.str(v, "value")
        guard ["ip", "cidr", "port", "dns", "sni"].contains(kind) else { return .failure(.init("Kind must be ip, cidr, port, dns or sni")) }
        if value.isEmpty { return .failure(.init("A value is required")) }
        if kind == "ip", !RuleDraft.isIP(value) { return .failure(.init("Value is not an IP address")) }
        if kind == "cidr", !RuleDraft.isCIDR(value) { return .failure(.init("Value is not a CIDR prefix")) }
        if kind == "port", Int(value).map({ !(1...65535).contains($0) }) ?? true { return .failure(.init("Port must be 1-65535")) }
        var d: [String: Any] = ["kind": kind, "value": value]
        for k in ["direction", "protocol", "since", "namespace", "pod", "workloadKind", "workloadName"] where !Form.str(v, k).isEmpty {
            d[k] = Form.str(v, k)
        }
        if let l = Form.int(v, "limit") {
            guard l >= 0 else { return .failure(.init("Max flows cannot be negative")) }
            if l > 0 { d["limit"] = l }
        } else if !Form.str(v, "limit").isEmpty { return .failure(.init("Max flows must be a number")) }
        return .success(c.request("POST", "api/v1/ebpf/deny/preview-history", body: Form.json(d)))
    }

    // MARK: Read-only: watchlist match (POST /api/v1/watchlist/match?limit=): raw feed text body

    public static func watchlistMatchRequest(_ c: NetraClient, feed: String, limit: Int = 200) -> Result<URLRequest, FormError> {
        let raw = feed.trimmingCharacters(in: .whitespacesAndNewlines)
        if raw.isEmpty { return .failure(.init("Paste IPs, CIDRs or names, one per line (or a JSON feed)")) }
        guard raw.utf8.count <= 1 << 20 else { return .failure(.init("Feed is larger than 1 MB")) }
        let q = limit == 200 ? [] : [URLQueryItem(name: "limit", value: String(min(max(limit, 1), 500)))]
        return .success(c.request("POST", "api/v1/watchlist/match", query: q, body: Data(raw.utf8)))
    }

    // MARK: Read-only: history export (GET /api/v1/policies/history/export)

    public static func exportHistory(_ c: NetraClient) async throws -> DownloadedFile {
        try await c.download("api/v1/policies/history/export")
    }

    // MARK: Guarded catalog

    public static let actions: [ControlAction] = [historyImport, aiDestinationDeny, baselineCapture, baselineClear, rateBaselineCapture, rateBaselineClear]

    public static func find(_ id: String) -> ControlAction? { actions.first { $0.id == id } }

    /// POST /policies/history/import?mode=merge|replace. Admin-only on the server. It rewrites the controller's
    /// rollback history only (no cluster change). Replace discards recorded history, so it is high risk and the
    /// server also demands X-Netra-Confirm-History-Replace: replace, which we always send in that mode.
    static let historyImport = ControlAction(
        id: "policy-history-import", group: "Policy history", title: "Import policy history",
        summary: "Load an exported history archive into the controller's rollback history. Merge appends; replace discards the existing history first. Nothing is applied to the cluster.",
        symbol: "square.and.arrow.down.on.square", maxRisk: .high,
        fields: [
            .init("archive", "Archive (JSON)", .multiline, help: "The file saved by Export policy history"),
            .init("mode", "Mode", .choice(["merge", "replace"]), initial: "merge"),
        ],
        build: { c, v in
            let text = Form.str(v, "archive")
            let info: PolicyToolsData.ArchiveInfo
            switch PolicyToolsData.inspectArchive(text) { case .failure(let e): return .failure(e); case .success(let i): info = i }
            let replace = Form.str(v, "mode") == "replace"
            if !replace, !Form.str(v, "mode").isEmpty, Form.str(v, "mode") != "merge" { return .failure(.init("Mode must be merge or replace")) }
            let body = Data(text.utf8)
            return .success(MutationSpec(
                title: replace ? "Replace policy history (\(info.revisions) revisions)" : "Merge policy history (\(info.revisions) revisions)",
                risk: replace ? .high : .medium, expectedPhrase: "replace history", leaseBound: false,
                preview: { c.request("GET", "api/v1/policies/history", query: [URLQueryItem(name: "limit", value: "200")]) },
                summarize: { PolicyToolsData.importSummary(info, replace: replace, current: $0) },
                execute: { _ in
                    var r = c.request("POST", "api/v1/policies/history/import", query: [URLQueryItem(name: "mode", value: replace ? "replace" : "merge")], body: body)
                    if replace { r.setValue("replace", forHTTPHeaderField: "X-Netra-Confirm-History-Replace") }
                    return r
                }))
        })

    /// POST /ebpf/ai-destinations/deny (no body). Adds SNI deny rules for every observed GenAI/MCP host.
    /// The server demands X-Netra-Confirm-Risk: high and mode=enforce with an active lease (409 otherwise).
    static let aiDestinationDeny = ControlAction(
        id: "ai-destinations-deny", group: "Policy history", title: "Deny observed AI destinations",
        summary: "Creates SNI deny rules for every GenAI/MCP host Netra has observed. Needs enforce mode with an active lease; the rules stop applying when the lease ends.",
        symbol: "brain.head.profile", maxRisk: .high, fields: [],
        build: { c, _ in
            .success(MutationSpec(
                title: "Deny observed AI destinations", risk: .high, expectedPhrase: "deny ai destinations", leaseBound: true,
                preview: { c.request("GET", "api/v1/ebpf/ai-destinations") },     // the read that lists exactly what would be denied
                summarize: PolicyToolsData.aiDestinationSummary,
                execute: { _ in c.request("POST", "api/v1/ebpf/ai-destinations/deny") }))
        })

    /// POST /insights/baseline (201). Re-captures the behavior baseline the anomaly insights compare against.
    static let baselineCapture = ControlAction(
        id: "baseline-capture", group: "Baselines", title: "Capture behavior baseline",
        summary: "Records what the fleet does now as the reference for behavior drift. Replaces any earlier baseline. Observe-only.",
        symbol: "camera.metering.center.weighted", maxRisk: .medium, fields: [],
        build: { c, _ in
            .success(MutationSpec(
                title: "Capture behavior baseline", risk: .medium, expectedPhrase: "", leaseBound: false,
                preview: { c.request("GET", "api/v1/insights/baseline") },
                summarize: { PolicyToolsData.baselineSummary($0, what: "behavior") + " Capturing replaces it with the current state." },
                execute: { _ in c.request("POST", "api/v1/insights/baseline") }))
        })

    /// DELETE /insights/baseline needs X-Netra-Confirm-Baseline-Clear: clear.
    static let baselineClear = ControlAction(
        id: "baseline-clear", group: "Baselines", title: "Clear behavior baseline",
        summary: "Deletes the captured behavior baseline; drift insights lose their reference until you capture a new one.",
        symbol: "trash", maxRisk: .high, fields: [],
        build: { c, _ in
            .success(MutationSpec(
                title: "Clear behavior baseline", risk: .high, expectedPhrase: "clear baseline", leaseBound: false,
                preview: { c.request("GET", "api/v1/insights/baseline") },
                summarize: { PolicyToolsData.baselineSummary($0, what: "behavior") + " Clearing it cannot be undone." },
                execute: { _ in
                    var r = c.request("DELETE", "api/v1/insights/baseline")
                    r.setValue("clear", forHTTPHeaderField: "X-Netra-Confirm-Baseline-Clear")
                    return r
                }))
        })

    /// POST /insights/rate-baseline?window= (201; 409 when there is not enough traffic data).
    static let rateBaselineCapture = ControlAction(
        id: "rate-baseline-capture", group: "Baselines", title: "Capture traffic-rate baseline",
        summary: "Records per-workload traffic rates over a window as the reference for rate anomalies. Replaces any earlier one. Observe-only.",
        symbol: "gauge.with.dots.needle.33percent", maxRisk: .medium,
        fields: [.init("window", "Window", initial: "5m", help: "30s to 2h, e.g. 5m or 1h30m")],
        build: { c, v in
            let w = Form.str(v, "window").isEmpty ? "5m" : Form.str(v, "window")
            guard PolicyToolsData.rateWindowSeconds(w) != nil else {
                return .failure(.init("Window must be between 30s and 2h (the server would silently use 5m otherwise)"))
            }
            return .success(MutationSpec(
                title: "Capture traffic-rate baseline (\(w))", risk: .medium, expectedPhrase: "", leaseBound: false,
                preview: { c.request("GET", "api/v1/insights/rate-baseline") },
                summarize: { PolicyToolsData.baselineSummary($0, what: "traffic-rate") + " Capturing replaces it using the last \(w) of traffic." },
                execute: { _ in c.request("POST", "api/v1/insights/rate-baseline", query: [URLQueryItem(name: "window", value: w)]) }))
        })

    /// DELETE /insights/rate-baseline needs X-Netra-Confirm-Rate-Baseline-Clear: clear.
    static let rateBaselineClear = ControlAction(
        id: "rate-baseline-clear", group: "Baselines", title: "Clear traffic-rate baseline",
        summary: "Deletes the captured traffic-rate baseline; rate anomalies lose their reference until you capture a new one.",
        symbol: "trash", maxRisk: .high, fields: [],
        build: { c, _ in
            .success(MutationSpec(
                title: "Clear traffic-rate baseline", risk: .high, expectedPhrase: "clear rate baseline", leaseBound: false,
                preview: { c.request("GET", "api/v1/insights/rate-baseline") },
                summarize: { PolicyToolsData.baselineSummary($0, what: "traffic-rate") + " Clearing it cannot be undone." },
                execute: { _ in
                    var r = c.request("DELETE", "api/v1/insights/rate-baseline")
                    r.setValue("clear", forHTTPHeaderField: "X-Netra-Confirm-Rate-Baseline-Clear")
                    return r
                }))
        })
}
