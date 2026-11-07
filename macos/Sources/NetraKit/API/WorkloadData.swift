// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Pure mapping/aggregation for the Workloads, Pods, L7, TLS and Diagnostics pages.
/// Every function tolerates missing fields: a server that omits a key yields an empty value, never a crash.
/// Metadata only: nothing here reads or builds payloads, argv or Secret contents.
public enum WorkloadData {
    /// Ordered severity used to colour (and label, never colour alone) findings and health.
    public enum Level: Int, Sendable, Comparable, CaseIterable {
        case ok, info, warn, critical
        public static func < (a: Level, b: Level) -> Bool { a.rawValue < b.rawValue }
        public var label: String { ["OK", "Info", "Warning", "Critical"][rawValue] }
        public var symbol: String { ["checkmark.circle", "info.circle", "exclamationmark.triangle", "xmark.octagon"][rawValue] }
    }

    /// Maps the server's mixed severity vocabularies (info/low/medium/high/critical, warn/warning) to a Level.
    public static func level(severity: String?) -> Level {
        switch (severity ?? "").lowercased() {
        case "critical", "high", "error", "fatal": .critical
        case "warn", "warning", "medium", "moderate": .warn
        case "info", "low", "notice": .info
        default: .ok
        }
    }

    // MARK: - shared helpers

    public static func items(_ v: JSONValue?, _ path: String = "items") -> [JSONValue] {
        if case .array(let a)? = v?.at(path) { return a }
        if path == "items", case .array(let a)? = v { return a }
        return []
    }

    public static func str(_ v: JSONValue?, _ path: String) -> String { v?.at(path).flatMap { $0 == .null ? nil : $0.summary } ?? "" }
    public static func num(_ v: JSONValue?, _ path: String) -> Double { v?.at(path)?.asDouble ?? 0 }

    /// "app=web, tier=fe" with keys sorted, "" when there are no labels.
    public static func labelsText(_ v: JSONValue?) -> String {
        guard case .object(let o)? = v else { return "" }
        return o.keys.sorted().map { "\($0)=\(o[$0]?.summary ?? "")" }.joined(separator: ", ")
    }

    public static func labelPairs(_ v: JSONValue?) -> [(key: String, value: String)] {
        guard case .object(let o)? = v else { return [] }
        return o.keys.sorted().map { ($0, o[$0]?.summary ?? "") }
    }

    public static func podKey(_ namespace: String, _ name: String) -> String { "\(namespace)/\(name)" }

    /// Adds fields to an object row (non-objects are returned unchanged).
    static func adding(_ row: JSONValue, _ extra: [String: JSONValue]) -> JSONValue {
        guard case .object(var o) = row else { return row }
        for (k, v) in extra { o[k] = v }
        return .object(o)
    }

    /// "namespace/pod" (or the owning workload when the pod is unknown) for an L7/diagnostic row; "" when unattributed.
    public static func workloadText(_ row: JSONValue) -> String {
        let ns = str(row, "namespace"), pod = str(row, "pod")
        let kind = str(row, "workloadKind"), name = str(row, "workloadName")
        let who = !name.isEmpty ? (kind.isEmpty ? name : "\(kind)/\(name)") : pod
        if who.isEmpty { return "" }
        return ns.isEmpty ? who : "\(ns)/\(who)"
    }

    /// Counts `path` over rows, largest first, ties by name. Empty values are grouped as `blank`.
    public static func countBy(_ rows: [ControlRow], path: String, blank: String = "(none)", top: Int = 8) -> [(name: String, count: Int)] {
        var m: [String: Int] = [:]
        for r in rows { let s = str(r.value, path); m[s.isEmpty ? blank : s, default: 0] += 1 }
        let sorted = m.map { (name: $0.key, count: $0.value) }.sorted { $0.count != $1.count ? $0.count > $1.count : $0.name < $1.name }
        return Array(sorted.prefix(top))
    }

    // MARK: - pods

    /// Pods that the server reports as locked down, as "namespace/name".
    public static func lockedDownPods(_ pods: JSONValue?) -> Set<String> {
        Set(items(pods).compactMap { p in
            if case .bool(true)? = p["lockedDown"] { return podKey(str(p, "namespace"), str(p, "name")) }
            return nil
        })
    }

    /// Health of a pod: failed/unknown are critical; pending, not-ready or crash-looping are warnings.
    public static func podHealth(phase: String, ready: Bool, restarts: Int) -> Level {
        switch phase.lowercased() {
        case "failed", "unknown": return .critical
        case "pending": return .warn
        case "succeeded": return .ok
        default: break
        }
        if !ready { return .warn }
        return restarts >= 5 ? .warn : .ok
    }

    /// Rows for /api/v1/pods with derived columns: owner, containers ready/total, labels text, health.
    public static func podRows(_ pods: JSONValue?) -> [ControlRow] {
        items(pods).enumerated().map { i, p in
            let ns = str(p, "namespace"), name = str(p, "name")
            let containers = items(p, "containers")
            let ready = containers.filter { if case .bool(true)? = $0["ready"] { true } else { false } }.count
            var restarts = Int(num(p, "restartCount"))
            if restarts == 0 { restarts = containers.reduce(0) { $0 + Int(num($1, "restartCount")) } }
            let isReady: Bool = { if case .bool(true)? = p["ready"] { true } else { false } }()
            let health = podHealth(phase: str(p, "phase"), ready: isReady, restarts: restarts)
            let owner = str(p, "ownerKind").isEmpty ? "" : "\(str(p, "ownerKind"))/\(str(p, "ownerName"))"
            let locked: Bool = { if case .bool(true)? = p["lockedDown"] { true } else { false } }()
            return ControlRow(id: podKey(ns, name) + "#\(i)", value: adding(p, [
                "owner": .string(owner),
                "containersText": .string(containers.isEmpty ? "" : "\(ready)/\(containers.count)"),
                "labelsText": .string(labelsText(p["labels"])),
                "health": .string(health.label),
                "healthRank": .number(Double(health.rawValue)),
                "restartTotal": .number(Double(restarts)),
                "lockedDownText": .string(locked ? "locked down" : ""),
            ]))
        }
    }

    public struct PodSummary: Equatable, Sendable {
        public var total = 0, running = 0, notReady = 0, failed = 0, pending = 0, restarts = 0, lockedDown = 0, namespaces = 0, nodes = 0
    }

    public static func podSummary(_ rows: [ControlRow]) -> PodSummary {
        var s = PodSummary(); var ns = Set<String>(), nodes = Set<String>()
        for r in rows {
            let v = r.value
            s.total += 1
            ns.insert(str(v, "namespace")); if !str(v, "node").isEmpty { nodes.insert(str(v, "node")) }
            switch str(v, "phase").lowercased() {
            case "running": s.running += 1
            case "failed", "unknown": s.failed += 1
            case "pending": s.pending += 1
            default: break
            }
            if case .bool(false)? = v["ready"], str(v, "phase").lowercased() == "running" { s.notReady += 1 }
            s.restarts += Int(num(v, "restartTotal"))
            if case .bool(true)? = v["lockedDown"] { s.lockedDown += 1 }
        }
        s.namespaces = ns.count; s.nodes = nodes.count
        return s
    }

    /// Parses the pod-logs event stream (`event: log` / `data: "<json string>"`, requested with follow=false).
    /// Returns the log lines plus any server-reported error. Unknown events are ignored.
    public static func parseLogStream(_ data: Data) -> (lines: [String], error: String?) {
        var lines: [String] = [], err: String?, event = ""
        for raw in String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: false) {
            if raw.hasPrefix("event:") { event = raw.dropFirst(6).trimmingCharacters(in: .whitespaces); continue }
            guard raw.hasPrefix("data:") else { continue }
            let payload = raw.dropFirst(5).trimmingCharacters(in: .whitespaces)
            let text: String = {
                if let d = payload.data(using: .utf8), let v = try? JSONDecoder().decode(JSONValue.self, from: d), case .string(let s) = v { return s }
                return payload
            }()
            if event == "log" { lines.append(text) } else if event == "error" { err = text }
        }
        return (lines, err)
    }

    // MARK: - workloads (observed identities from /api/v1/ebpf/workloads)

    /// Rows for the observed workload identities, joined with the pod inventory to show lockdown and readiness.
    public static func workloadRows(workloads: JSONValue?, pods: JSONValue?) -> [ControlRow] {
        let locked = lockedDownPods(pods)
        var podInfo: [String: JSONValue] = [:]
        for p in items(pods) { podInfo[podKey(str(p, "namespace"), str(p, "name"))] = p }
        return items(workloads).enumerated().map { i, w in
            let ns = str(w, "namespace"), pod = str(w, "pod")
            let key = podKey(ns, pod)
            let kind = str(w, "workloadKind"), name = str(w, "workloadName")
            let info = podInfo[key]
            var extra: [String: JSONValue] = [
                "owner": .string(name.isEmpty ? "" : (kind.isEmpty ? name : "\(kind)/\(name)")),
                "labelsText": .string(labelsText(w["labels"])),
                "lockedDown": .bool(locked.contains(key)),
                "lockedDownText": .string(locked.contains(key) ? "locked down" : ""),
            ]
            if let info {
                extra["phase"] = info["phase"] ?? .null
                extra["ready"] = info["ready"] ?? .null
                extra["podIP"] = info["podIP"] ?? .null
            }
            if str(w, "node").isEmpty, let n = info?["node"] { extra["node"] = n }
            return ControlRow(id: (str(w, "uid").isEmpty ? key : str(w, "uid")) + "#\(i)", value: adding(w, extra))
        }
    }

    public struct WorkloadSummary: Equatable, Sendable {
        public var pods = 0, namespaces = 0, owners = 0, nodes = 0, lockedDown = 0, unowned = 0
    }

    public static func workloadSummary(_ rows: [ControlRow]) -> WorkloadSummary {
        var s = WorkloadSummary(); var ns = Set<String>(), owners = Set<String>(), nodes = Set<String>()
        for r in rows {
            s.pods += 1; ns.insert(str(r.value, "namespace"))
            let o = str(r.value, "owner")
            if o.isEmpty { s.unowned += 1 } else { owners.insert(str(r.value, "namespace") + "/" + o) }
            if !str(r.value, "node").isEmpty { nodes.insert(str(r.value, "node")) }
            if case .bool(true)? = r.value["lockedDown"] { s.lockedDown += 1 }
        }
        s.namespaces = ns.count; s.owners = owners.count; s.nodes = nodes.count
        return s
    }

    /// Detail request path for a pod workload. Segments are percent-encoded.
    public static func detailPath(kind: String, namespace: String, name: String) -> String {
        let enc: (String) -> String = { $0.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/"))) ?? $0 }
        return "api/v1/workloads/\(enc(kind.lowercased()))/\(enc(namespace))/\(enc(name))"
    }

    public static func logsPath(namespace: String, name: String) -> String {
        let enc: (String) -> String = { $0.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/"))) ?? $0 }
        return "api/v1/pods/\(enc(namespace))/\(enc(name))/logs"
    }

    // MARK: - L7

    /// HTTP/1 status counts grouped by class ("2xx"...), always in 1xx..5xx order, plus "other" when needed.
    public static func httpStatusClasses(_ rows: [JSONValue]) -> [(name: String, count: Double)] {
        var m: [String: Double] = [:]
        for r in rows {
            let s = Int(num(r, "status")); let c = Double(num(r, "count"))
            m[(100..<600).contains(s) ? "\(s / 100)xx" : "other", default: 0] += c
        }
        let order = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"]
        return order.compactMap { k in m[k].map { (k, $0) } }
    }

    /// 5xx / all statuses, 0 when none were seen.
    public static func errorRatio(_ rows: [JSONValue]) -> Double {
        let all = rows.reduce(0) { $0 + num($1, "count") }
        let bad = rows.filter { num($0, "status") >= 500 }.reduce(0) { $0 + num($1, "count") }
        return all > 0 ? bad / all : 0
    }

    /// Adds `workload` (and a `blockedRatio` when the row carries blocked/handshakes/attempts) to metadata rows.
    public static func l7Rows(_ rows: [JSONValue], totalKey: String? = nil) -> [ControlRow] {
        rows.enumerated().map { i, r in
            var extra: [String: JSONValue] = ["workload": .string(workloadText(r))]
            if let totalKey, num(r, totalKey) > 0 { extra["blockedRatio"] = .number(num(r, "blocked") / num(r, totalKey)) }
            if num(r, "status") >= 100 { extra["statusClass"] = .string("\(Int(num(r, "status")) / 100)xx") }
            return ControlRow(id: "\(i)", value: adding(r, extra))
        }
    }

    /// Rows for /api/v1/l7/sampled protocols: adds the error ratio of responses and the served/issued role.
    public static func sampledProtocolRows(_ v: JSONValue?) -> [ControlRow] {
        items(v, "protocols").enumerated().map { i, p in
            let resp = num(p, "responses")
            return ControlRow(id: "\(i)", value: adding(p, [
                "errorRatio": .number(resp > 0 ? num(p, "errors") / resp : 0),
                "name": .string("\(str(p, "protocol")) (\(str(p, "role")))"),
            ]))
        }
    }

    /// Top operations across all sampled protocols with the estimated (scaled) request counts.
    public static func sampledTopOps(_ v: JSONValue?, top: Int = 10) -> [(label: String, estimated: Double)] {
        var out: [(String, Double)] = []
        for p in items(v, "protocols") {
            for o in items(p, "ops") { out.append(("\(str(p, "protocol")) \(str(o, "op"))", num(o, "estimated"))) }
        }
        return Array(out.sorted { $0.1 != $1.1 ? $0.1 > $1.1 : $0.0 < $1.0 }.prefix(top)).map { (label: $0.0, estimated: $0.1) }
    }

    // MARK: - TLS fingerprints

    /// TLS legacy version number to a name ("0x0303" -> "TLS 1.2").
    public static func tlsVersion(_ v: Double) -> String {
        switch Int(v) {
        case 0x0300: "SSL 3.0"
        case 0x0301: "TLS 1.0"
        case 0x0302: "TLS 1.1"
        case 0x0303: "TLS 1.2"
        case 0x0304: "TLS 1.3"
        case 0: ""
        default: String(format: "0x%04x", Int(v))
        }
    }

    /// Fingerprint rows joined with the risk board on JA3. Risk items win for severity; every row gets a level.
    public static func tlsRows(fingerprints: JSONValue?, risk: JSONValue?) -> [ControlRow] {
        var riskByJA3: [String: JSONValue] = [:]
        for r in items(risk) { riskByJA3[str(r, "ja3")] = r }
        return items(fingerprints, "fingerprints").enumerated().map { i, f in
            let ja3 = str(f, "ja3")
            let r = riskByJA3[ja3]
            var sev = r.map { level(severity: str($0, "severity")) } ?? .ok
            if case .bool(true)? = f["ech"], sev < .warn { sev = .warn }
            let reasons: String = items(r, "reasons").map { $0.summary }.joined(separator: ", ")
            let proto: String = { if case .bool(true)? = f["quic"] { return "QUIC" }; return "TCP" }()
            return ControlRow(id: ja3 + "#\(i)", value: adding(f, [
                "ja3Short": .string(String(ja3.prefix(12))),
                "versionText": .string(tlsVersion(num(f, "version"))),
                "riskLevel": .string(sev.label),
                "riskRank": .number(Double(sev.rawValue)),
                "reasons": .string(reasons),
                "transport": .string(proto),
            ]))
        }
    }

    public struct TLSSummary: Equatable, Sendable {
        public var unique = 0, ech = 0, rare = 0, quic = 0, missingSNI = 0, observations = 0, enabled = true
    }

    public static func tlsSummary(fingerprints: JSONValue?, risk: JSONValue?) -> TLSSummary {
        let fps = items(fingerprints, "fingerprints")
        var s = TLSSummary()
        s.unique = Int(num(fingerprints, "stats.uniqueJa3")); if s.unique == 0 { s.unique = fps.count }
        if case .bool(false)? = fingerprints?.at("stats.enabled") { s.enabled = false }
        s.ech = Int(num(risk, "echSightings")); s.rare = Int(num(risk, "rare"))
        if s.ech == 0 { s.ech = fps.filter { if case .bool(true)? = $0["ech"] { true } else { false } }.count }
        s.quic = fps.filter { if case .bool(true)? = $0["quic"] { true } else { false } }.count
        s.missingSNI = fps.filter { str($0, "sni").isEmpty }.count
        s.observations = Int(fps.reduce(0) { $0 + num($1, "count") })
        return s
    }

    // MARK: - diagnostics

    public static func protoName(_ n: Double) -> String {
        switch Int(n) { case 6: "tcp"; case 17: "udp"; case 1: "icmp"; case 58: "icmpv6"; default: "\(Int(n))" }
    }

    /// Drop detective findings with readable protocol/direction and a level (exact = critical-ish, probable = warn).
    public static func detectiveRows(_ v: JSONValue?) -> [ControlRow] {
        items(v, "findings").enumerated().map { i, f in
            let lvl: Level = str(f, "confidence") == "exact" ? .warn : .info
            return ControlRow(id: "\(i)", value: adding(f, [
                "protocolName": .string(protoName(num(f, "protocol"))),
                "directionName": .string(num(f, "direction") == 1 ? "ingress" : "egress"),
                "workload": .string(workloadText(f)),
                "level": .string(lvl.label),
                "levelRank": .number(Double(lvl.rawValue)),
            ]))
        }
    }

    /// TCP pressure rows: adds cwnd utilisation (packetsOut/cwnd) and a "remote" endpoint string.
    public static func pressureRows(_ v: JSONValue?) -> [ControlRow] {
        items(v, "pressure").enumerated().map { i, p in
            let cwnd = num(p, "sendCwnd")
            return ControlRow(id: "\(i)", value: adding(p, [
                "cwndUse": .number(cwnd > 0 ? num(p, "packetsOut") / cwnd : 0),
                "remote": .string(endpoint(str(p, "remoteIp"), num(p, "remotePort"))),
                "workload": .string(workloadText(p)),
            ]))
        }
    }

    /// Connect-latency rows: adds mean latency in ms and the remote endpoint.
    public static func connectRows(_ v: JSONValue?) -> [ControlRow] {
        items(v, "connect").enumerated().map { i, c in
            let n = num(c, "established")
            return ControlRow(id: "\(i)", value: adding(c, [
                "avgMs": .number(n > 0 ? num(c, "totalLatencyUs") / n / 1000 : 0),
                "maxMs": .number(num(c, "maxLatencyUs") / 1000),
                "remote": .string(endpoint(str(c, "remoteIp"), num(c, "remotePort"))),
                "workload": .string(workloadText(c)),
            ]))
        }
    }

    /// Per node IPv6 extension-header rows, flattened with the node name and fragment ratio.
    public static func ipv6Rows(_ v: JSONValue?) -> [ControlRow] {
        var out: [ControlRow] = []
        for n in items(v, "nodes") {
            for h in items(n, "extHeaders") {
                let pk = num(h, "packets")
                out.append(ControlRow(id: "\(out.count)", value: adding(h, [
                    "node": .string(str(n, "node")),
                    "fragmentRatio": .number(pk > 0 ? num(h, "fragmented") / pk : 0),
                ])))
            }
        }
        return out
    }

    /// Kernel-network findings flattened across nodes (read-only guidance; Netra never applies it).
    public static func kernelFindingRows(_ v: JSONValue?) -> [ControlRow] {
        var out: [ControlRow] = []
        for n in items(v, "nodes") {
            for f in items(n, "findings") {
                let lvl = level(severity: str(f, "severity"))
                let evidence = items(f, "evidence").map { $0.summary }.joined(separator: "\n")
                out.append(ControlRow(id: "\(out.count)", value: adding(f, [
                    "node": .string(str(n, "node")),
                    "levelRank": .number(Double(lvl.rawValue)),
                    "level": .string(lvl.label),
                    "evidenceText": .string(evidence),
                ])))
            }
        }
        return out.sorted { num($0.value, "levelRank") > num($1.value, "levelRank") }
    }

    /// Anomalies from path/IPv6 summaries ("summary.anomalies"), most severe first.
    public static func anomalyRows(_ v: JSONValue?) -> [ControlRow] {
        items(v, "summary.anomalies").enumerated().map { i, a in
            let lvl = level(severity: str(a, "severity"))
            return ControlRow(id: "\(i)", value: adding(a, ["level": .string(lvl.label), "levelRank": .number(Double(lvl.rawValue))]))
        }.sorted { num($0.value, "levelRank") > num($1.value, "levelRank") }
    }

    static func endpoint(_ ip: String, _ port: Double) -> String {
        if ip.isEmpty { return "" }
        let p = Int(port)
        if p == 0 { return ip }
        return ip.contains(":") ? "[\(ip)]:\(p)" : "\(ip):\(p)"
    }

    /// Headline "health" for the diagnostics page: worst level across findings and anomalies.
    public static func worstLevel(_ rows: [ControlRow], path: String = "level") -> Level {
        rows.map { r in Level.allCases.first { $0.label == str(r.value, path) } ?? .ok }.max() ?? .ok
    }
}
