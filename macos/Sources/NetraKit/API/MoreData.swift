// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Pure helpers for the TCP events, connections, path, congestion, coverage, explain and investigate pages.
/// Shapes come from internal/api (tcp_events.go, investigate.go), internal/nsheat, coverage, models.PathDiagnosticsResponse.
public enum MoreData {
    /// Friendly text for a failed GET. 404/409 mean the feature is not enabled on the controller.
    public static func friendlyError(status: Int, message: String, feature: String) -> String {
        switch status {
        case 404, 409: return "\(feature) is not enabled on this controller (HTTP \(status)). \(message)".trimmingCharacters(in: .whitespaces)
        case 403: return "Your token's scope does not allow \(feature). \(message)".trimmingCharacters(in: .whitespaces)
        case 400: return "The controller rejected the query: \(message)"
        case 503: return "\(feature) is temporarily unavailable (HTTP 503). \(message)".trimmingCharacters(in: .whitespaces)
        default: return "HTTP \(status): \(message)"
        }
    }

    /// Copy of an object row with extra fields; non-objects pass through.
    static func adding(_ row: JSONValue, _ extra: [String: JSONValue]) -> JSONValue {
        guard case .object(var o) = row else { return row }
        for (k, v) in extra { o[k] = v }
        return .object(o)
    }

    /// "ip:port", "ip" when the port is 0/absent, "" when both are missing.
    public static func endpoint(_ ip: JSONValue?, _ port: JSONValue?) -> String {
        guard let ip = ip?.string, !ip.isEmpty else { return "" }
        let p = Int(port?.asDouble ?? 0)
        if p <= 0 { return ip }
        return ip.contains(":") ? "[\(ip)]:\(p)" : "\(ip):\(p)"
    }

    /// Sampled events from `GET /api/v1/agents` (`items[].events[]`), flattened, newest first, with `node`,
    /// `src`, `dst` and `workload` added. Stale agents are kept but flagged (`stale`). Capped at `limit`.
    public static func agentEvents(_ agents: JSONValue, limit: Int = 1000) -> [ControlRow] {
        var out: [(Date, ControlRow)] = []
        for (ai, a) in agents.rows(at: "items").enumerated() {
            let node = a.value["node"]?.string ?? "?"
            guard case .array(let events)? = a.value["events"] else { continue }
            for (ei, e) in events.enumerated() {
                let ns = e["namespace"]?.string ?? "", pod = e["pod"]?.string ?? ""
                let workload = pod.isEmpty ? "" : (ns.isEmpty ? pod : "\(ns)/\(pod)")
                let row = adding(e, [
                    "node": .string(node),
                    "src": .string(endpoint(e["sourceIp"], e["sourcePort"])),
                    "dst": .string(endpoint(e["destinationIp"], e["destinationPort"])),
                    "workload": .string(workload),
                    "stale": a.value["stale"] ?? .bool(false),
                ])
                out.append((CellFormat.date(e["observedAt"]) ?? .distantPast, ControlRow(id: "\(ai):\(node):\(ei)", value: row)))
            }
        }
        out.sort { $0.0 > $1.0 }
        return Array(out.prefix(max(limit, 0)).map(\.1))
    }

    public struct EventStats: Equatable, Sendable {
        public var total = 0, blocked = 0, workloads = 0, nodes = 0
    }

    public static func eventStats(_ rows: [ControlRow]) -> EventStats {
        var s = EventStats(); var w = Set<String>(), n = Set<String>()
        for r in rows {
            s.total += 1
            if r.value["action"]?.string == "blocked" { s.blocked += 1 }
            if let x = r.value["workload"]?.string, !x.isEmpty { w.insert(x) }
            if let x = r.value["node"]?.string { n.insert(x) }
        }
        s.workloads = w.count; s.nodes = n.count
        return s
    }

    /// Flattens `parent[].child[]` (e.g. interfaces.nodes[].interfaces[]), copying `node` onto each child.
    public static func nested(_ v: JSONValue, parent: String = "nodes", child: String, key: String = "node") -> [ControlRow] {
        var out: [ControlRow] = []
        for (pi, p) in v.rows(at: parent).enumerated() {
            let name = p.value[key]?.string ?? "?"
            guard case .array(let kids)? = p.value[child] else { continue }
            for (ci, k) in kids.enumerated() {
                out.append(ControlRow(id: "\(pi):\(name):\(ci)", value: adding(k, [key: .string(name)])))
            }
        }
        return out
    }

    /// Adds `<key>Text` (comma-joined) for a string array or string map field, so a table can show it.
    public static func joined(_ rows: [ControlRow], key: String) -> [ControlRow] {
        rows.map { r in
            var text = ""
            switch r.value[key] {
            case .array(let a)?: text = a.compactMap(\.string).joined(separator: ", ")
            case .object(let o)?: text = o.keys.sorted().map { "\($0): \(o[$0]?.string ?? "")" }.joined(separator: "; ")
            default: break
            }
            return ControlRow(id: r.id, value: adding(r.value, [key + "Text": .string(text)]))
        }
    }

    /// The TCP event sensor's own health: non-zero read errors, bad family or map-full means the counts undercount.
    public static func tcpUndercountWarning(_ v: JSONValue) -> String? {
        let t = v["totals"]
        let parts = [("read errors", "readErrors"), ("unknown address families", "badFamily"), ("map-full drops", "mapFull")]
            .compactMap { name, key -> String? in
                let n = Int(t?[key]?.asDouble ?? 0); return n > 0 ? "\(n) \(name)" : nil
            }
        return parts.isEmpty ? nil : "The sensor reported " + parts.joined(separator: ", ") + ". Counts below are an undercount."
    }

    /// Fresh nodes that are not running the TCP event sensor. Silence from them is not a healthy signal.
    public static func tcpSilentNodes(_ v: JSONValue) -> [String] {
        v.rows(at: "nodes", idKeys: ["node"]).filter { $0.value["reporting"] != .bool(true) }.compactMap { $0.value["node"]?.string }
    }

    /// packetsOut as a share of the congestion window (0...n), nil when cwnd is unknown.
    public static func cwndRatio(_ row: JSONValue) -> Double? {
        guard let cwnd = row["sendCwnd"]?.asDouble, cwnd > 0 else { return nil }
        return (row["packetsOut"]?.asDouble ?? 0) / cwnd
    }

    /// Adds `cwndRatio`, `flow` (remote endpoint), `workload` and `avgConnectUs` to pressure/connect rows.
    public static func pathRows(_ v: JSONValue, at path: String) -> [ControlRow] {
        v.rows(at: path).map { r in
            let ns = r.value["namespace"]?.string ?? "", pod = r.value["pod"]?.string ?? ""
            let workload = pod.isEmpty ? "cgroup \(Int(r.value["cgroupId"]?.asDouble ?? 0))" : "\(ns)/\(pod)"
            var extra: [String: JSONValue] = ["workload": .string(workload), "remote": .string(endpoint(r.value["remoteIp"], r.value["remotePort"]))]
            if let ratio = cwndRatio(r.value) { extra["cwndRatio"] = .number(ratio) }
            if let n = r.value["established"]?.asDouble, n > 0, let t = r.value["totalLatencyUs"]?.asDouble { extra["avgConnectUs"] = .number(t / n) }
            return ControlRow(id: r.id, value: adding(r.value, extra))
        }
    }

    /// Microseconds as "1.2 ms" / "340 us".
    public static func micros(_ us: Double) -> String {
        us >= 1000 ? String(format: "%.1f ms", us / 1000) : "\(Int(us.rounded())) us"
    }

    /// Hottest namespaces first by blocked then packets (the server already sorts by packets).
    public static func hottestNamespace(_ heat: JSONValue) -> String? {
        heat.rows(at: "rows", idKeys: ["namespace"]).max { a, b in
            let (ab, bb) = (a.value["blocked"]?.asDouble ?? 0, b.value["blocked"]?.asDouble ?? 0)
            return ab != bb ? ab < bb : (a.value["packets"]?.asDouble ?? 0) < (b.value["packets"]?.asDouble ?? 0)
        }?.value["namespace"]?.string
    }

    // MARK: Query builders for the pages that take user input

    public struct Query: Equatable, Sendable {
        public var items: [URLQueryItem]
        public var error: String?
    }

    /// Go's time.ParseDuration subset: one or more `<number><unit>` terms, e.g. 15m, 1h30m, 90s.
    public static func isGoDuration(_ s: String) -> Bool {
        s.range(of: #"^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$"#, options: .regularExpression) != nil
    }

    /// `GET /api/v1/investigate/connection` takes namespace, pod, peer, port, node and window (not a full 5-tuple).
    public static func investigateQuery(namespace: String, pod: String, peer: String, port: String, node: String, window: String) -> Query {
        func t(_ s: String) -> String { s.trimmingCharacters(in: .whitespacesAndNewlines) }
        var items: [URLQueryItem] = []
        for (k, v) in [("namespace", namespace), ("pod", pod), ("peer", peer), ("node", node)] where !t(v).isEmpty {
            items.append(.init(name: k, value: t(v)))
        }
        if !t(port).isEmpty {
            guard let p = Int(t(port)), (1...65535).contains(p) else { return Query(items: [], error: "Port must be a number from 1 to 65535.") }
            items.append(.init(name: "port", value: String(p)))
        }
        if !t(window).isEmpty {
            guard isGoDuration(t(window)) else { return Query(items: [], error: "Window must be a duration such as 15m, 1h or 90s.") }
            items.append(.init(name: "window", value: t(window)))
        }
        if t(namespace).isEmpty, t(pod).isEmpty, t(peer).isEmpty, t(node).isEmpty, t(port).isEmpty {
            return Query(items: [], error: "Enter at least one of namespace, pod, peer, port or node.")
        }
        return Query(items: items, error: nil)
    }

    /// `GET /api/v1/ebpf/explain` takes namespace, pod, limit (1...100) and agentLimit.
    public static func explainQuery(namespace: String, pod: String, limit: Int) -> [URLQueryItem] {
        var items: [URLQueryItem] = []
        let ns = namespace.trimmingCharacters(in: .whitespaces), p = pod.trimmingCharacters(in: .whitespaces)
        if !ns.isEmpty { items.append(.init(name: "namespace", value: ns)) }
        if !p.isEmpty { items.append(.init(name: "pod", value: p)) }
        items.append(.init(name: "limit", value: String(min(max(limit, 1), 100))))
        return items
    }

    /// Investigation events oldest first (a timeline reads forwards).
    public static func timeline(_ v: JSONValue) -> [ControlRow] {
        v.rows(at: "events", idKeys: ["stage"]).sorted {
            (CellFormat.date($0.value["ts"]) ?? .distantPast) < (CellFormat.date($1.value["ts"]) ?? .distantPast)
        }
    }

    /// Investigation / drop-explain lists of plain strings (limitations, notes, nextSteps).
    public static func strings(_ v: JSONValue, at path: String) -> [String] {
        guard case .array(let a)? = v.at(path) else { return [] }
        return a.compactMap(\.string).filter { !$0.isEmpty }
    }
}
