// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Pure helpers for the read-only coverage pages (insights detail, process watch, datapath detail, fleet flows,
/// metric exporters). Every field name comes from internal/api handlers and the structs they return
/// (models.CapChangeEvent, flowlog.REDRow, scandetect.Finding, automitigate.PreviewResult, ...). Nothing here
/// issues a request or mutates anything.
public enum CoverageData {
    // MARK: Errors

    /// 404/409/503 on these routes mean the feature or its backing service is off (scan detector, metrics, kube).
    public static func isFeatureOff(status: Int) -> Bool { [404, 409, 503].contains(status) }

    public static func friendlyError(status: Int, message: String, feature: String) -> String {
        switch status {
        case 503: return "\(feature) is not enabled on this controller (HTTP 503). \(message)".trimmingCharacters(in: .whitespaces)
        case 502: return "\(feature) needs a backing service the controller cannot reach (HTTP 502). \(message)".trimmingCharacters(in: .whitespaces)
        default: return MoreData.friendlyError(status: status, message: message, feature: feature)
        }
    }

    // MARK: Small readers

    public static func int(_ v: JSONValue?) -> Int { Int((v?.asDouble ?? 0).rounded()) }
    public static func bool(_ v: JSONValue?) -> Bool { if case .bool(let b)? = v { b } else { false } }
    public static func strings(_ v: JSONValue?) -> [String] { if case .array(let a)? = v { a.compactMap { $0.string } } else { [] } }

    /// The `limitations` / `note` / `caveat` strings a response carries, in a stable order, empties dropped.
    public static func notes(_ v: JSONValue, keys: [String] = ["limitations", "limitation", "note", "caveat"]) -> [String] {
        var out: [String] = []
        for k in keys {
            if let s = v[k]?.string, !s.isEmpty { out.append(s) } else { out += strings(v[k]).filter { !$0.isEmpty } }
        }
        return out
    }

    static func adding(_ row: JSONValue, _ extra: [String: JSONValue]) -> JSONValue {
        guard case .object(var o) = row else { return row }
        for (k, v) in extra { o[k] = v }
        return .object(o)
    }

    // MARK: Process drift (capdrift / nsdrift / exehash)

    /// Linux capability names by bit number (include/uapi/linux/capability.h).
    static let capNames = ["CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "SETPCAP",
        "LINUX_IMMUTABLE", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER", "SYS_MODULE",
        "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT", "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME",
        "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG",
        "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF", "CHECKPOINT_RESTORE"]

    /// Names of the capability bits set in `mask`; bits beyond the table show as `BIT<n>`.
    public static func capabilities(_ mask: UInt64) -> [String] {
        (0..<64).filter { mask & (1 << UInt64($0)) != 0 }.map { $0 < capNames.count ? "CAP_" + capNames[$0] : "BIT\($0)" }
    }

    /// Capability events with `workload`, `gained`, `lost` (names) and hex masks added.
    public static func capEventRows(_ v: JSONValue) -> [ControlRow] {
        v.rows(at: "events", idKeys: ["pid"]).map { r in
            let prev = UInt64(max(r.value["previousCapEff"]?.asDouble ?? 0, 0)), cur = UInt64(max(r.value["currentCapEff"]?.asDouble ?? 0, 0))
            return ControlRow(id: r.id, value: adding(r.value, [
                "workload": .string(workload(r.value)),
                "gained": .string(capabilities(cur & ~prev).joined(separator: ", ")),
                "lost": .string(capabilities(prev & ~cur).joined(separator: ", ")),
                "previousHex": .string("0x" + String(prev, radix: 16)),
                "currentHex": .string("0x" + String(cur, radix: 16)),
            ]))
        }
    }

    /// Exe-hash events with short previous/current digests (the full digest stays in the inspector).
    public static func exeEventRows(_ v: JSONValue) -> [ControlRow] {
        v.rows(at: "events", idKeys: ["pid"]).map { r in
            ControlRow(id: r.id, value: adding(r.value, [
                "workload": .string(workload(r.value)),
                "previousShort": .string(String((r.value["previousExeHash"]?.string ?? "").prefix(12))),
                "currentShort": .string(String((r.value["currentExeHash"]?.string ?? "").prefix(12))),
            ]))
        }
    }

    public static func nsEventRows(_ v: JSONValue) -> [ControlRow] {
        v.rows(at: "events", idKeys: ["pid"]).map { r in
            ControlRow(id: r.id, value: adding(r.value, ["workload": .string(workload(r.value))]))
        }
    }

    /// "namespace/pod" or "kind/name" for a drift event, whichever the event carries.
    public static func workload(_ e: JSONValue) -> String {
        let ns = e["namespace"]?.string ?? "", pod = e["pod"]?.string ?? ""
        if !pod.isEmpty { return ns.isEmpty ? pod : "\(ns)/\(pod)" }
        let kind = e["workloadKind"]?.string ?? "", name = e["workloadName"]?.string ?? ""
        return name.isEmpty ? "" : (kind.isEmpty ? name : "\(kind)/\(name)")
    }

    // MARK: Insights

    /// `{"captured": false, "baseline": null}` vs a captured baseline.
    public struct BaselineInfo: Equatable, Sendable {
        public var captured: Bool
        public var capturedAt: String
        public var schemaVersion: Int
        public var windowSeconds: Int
        public var entries: Int
    }

    public static func baselineInfo(_ v: JSONValue) -> BaselineInfo {
        let b = v["baseline"]
        let entries: Int = { if case .array(let a)? = b?["entries"] { a.count } else { 0 } }()
        return BaselineInfo(captured: bool(v["captured"]), capturedAt: b?["capturedAt"]?.string ?? "", schemaVersion: int(b?["schemaVersion"]),
                            windowSeconds: int(b?["windowSeconds"]), entries: entries)
    }

    /// Distinct trace ids among spans, and how many spans are inferred (call chains are inferred, not propagated headers).
    public static func traceStats(_ v: JSONValue) -> (traces: Int, spans: Int, inferred: Int) {
        let spans = DetectData.rows(v, "spans")
        return (Set(spans.compactMap { $0["traceId"]?.string }).count, spans.count, spans.filter { bool($0["inferred"]) }.count)
    }

    /// Candidate rows for the policy-review picker from GET insights/recommendations (`items[]`).
    public struct Recommendation: Identifiable, Equatable, Sendable {
        public var id: String
        public var label: String
    }

    public static func recommendations(_ v: JSONValue) -> [Recommendation] {
        DetectData.rows(v, "items").compactMap { r in
            guard let id = r["id"]?.string, !id.isEmpty else { return nil }
            let ns = r["namespace"]?.string ?? "", wl = r["workloadName"]?.string ?? id
            return Recommendation(id: id, label: ns.isEmpty ? wl : "\(ns)/\(wl)")
        }
    }

    /// Plan fields of a policy review as label/value pairs. The manifest and revision manifests are never shown.
    public static func planItems(_ v: JSONValue) -> [(label: String, value: String)] {
        guard let p = v["plan"] else { return [] }
        func yn(_ k: String) -> String { bool(p[k]) ? "yes" : "no" }
        return [
            ("Policy", [p["namespace"]?.string, p["name"]?.string].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: "/")),
            ("Exists", yn("exists")), ("Risk", p["risk"]?.string ?? ""),
            ("Egress rules now", String(int(p["currentEgressRules"]))), ("Egress rules proposed", String(int(p["proposedEgressRules"]))),
            ("Selector changed", yn("selectorChanged")), ("Spec changed", yn("specChanged")),
        ]
    }

    // MARK: Scan detector / auto-mitigate preview

    /// "attack type: count" pairs from scan snapshot `findingsTotal`.
    public static func findingTotals(_ v: JSONValue) -> [(type: String, count: Int)] {
        guard case .object(let o)? = v.at("snapshot.findingsTotal") else { return [] }
        return o.keys.sorted().map { ($0, int(o[$0])) }
    }

    /// Candidates that would act (no skip reason), versus those skipped.
    public static func candidateSplit(_ v: JSONValue) -> (wouldAct: Int, skipped: Int) {
        let c = DetectData.rows(v, "candidates")
        let skipped = c.filter { !($0["skipped"]?.string ?? "").isEmpty }.count
        return (c.count - skipped, skipped)
    }

    // MARK: Datapath

    /// Rows of GET ebpf/census as grouped label/value pairs (counts of programmed deny and allow entries).
    public static func censusGroups(_ v: JSONValue) -> [(title: String, items: [(label: String, value: String)])] {
        func item(_ label: String, _ key: String) -> (label: String, value: String) { (label, String(int(v[key]))) }
        return [
            ("Denied", [item("IPv4", "blockedIPv4"), item("IPv6", "blockedIPv6"), item("CIDRs", "blockedCidrs"), item("Ports", "blockedPorts"),
                        item("DNS", "blockedDns"), item("UIDs", "blockedUids"), item("Ingress IPv4", "blockedIngressIPv4"),
                        item("Ingress IPv6", "blockedIngressIPv6"), item("Total", "totalDenied")]),
            ("Allowed", [item("IPv4", "allowedIPv4"), item("IPv6", "allowedIPv6"), item("CIDRs", "allowedCidrs"), item("Ports", "allowedPorts"),
                         item("Total", "totalAllowed")]),
        ]
    }

    /// Queue-depth bucket counts of one node in ebpf/stack-histograms (`listenDepthBuckets[]` = label, count).
    public static func depthBuckets(_ node: JSONValue) -> [(label: String, count: Int)] {
        DetectData.rows(node, "listenDepthBuckets").map { ($0["label"]?.string ?? "", int($0["count"])) }
    }

    /// Series of a sparkline (`windows[]`) for one rate field, oldest first. Windows without a usable end time are skipped.
    public static func sparkline(_ v: JSONValue, field: String) -> [(at: Date, value: Double)] {
        DetectData.rows(v, "windows").compactMap { w in
            guard let at = CellFormat.date(w["endAt"]) ?? CellFormat.date(w["startAt"]), let y = w[field]?.asDouble else { return nil }
            return (at, y)
        }.sorted { $0.at < $1.at }
    }

    /// Rate fields a kernel-network sparkline window carries.
    public static let sparklineFields: [(field: String, title: String)] = [
        ("softnetDroppedPerSecond", "Softnet dropped /s"), ("softnetTimeSqueezePerSecond", "Softnet time squeeze /s"),
        ("rxDroppedPerSecond", "RX dropped /s"), ("txDroppedPerSecond", "TX dropped /s"),
        ("rxMissedPerSecond", "RX missed /s"), ("qdiscDropsPerSecond", "Qdisc drops /s"),
    ]

    /// Node names from GET api/v1/agents (`items[].node`), sorted, de-duplicated.
    public static func nodeNames(_ agents: JSONValue) -> [String] {
        Array(Set(DetectData.rows(agents, "items").compactMap { $0["node"]?.string }.filter { !$0.isEmpty })).sorted()
    }

    /// Estimated error ratio of a sampled L7 protocol row (errors / responses), nil when nothing responded.
    public static func errorRatio(_ row: JSONValue) -> Double? {
        let r = row["responses"]?.asDouble ?? 0
        return r > 0 ? (row["errors"]?.asDouble ?? 0) / r : nil
    }

    // MARK: Fleet and exporters

    /// Cluster contribution summary for fleet flow history: (ok, failed).
    public static func clusterHealth(_ v: JSONValue) -> (ok: Int, failed: Int) {
        let c = DetectData.rows(v, "clusters")
        let ok = c.filter { bool($0["ok"]) }.count
        return (ok, c.count - ok)
    }

    /// Total points sent and failures over every exporter sink.
    public static func exporterTotals(_ v: JSONValue) -> (sent: Int, failures: Int) {
        let e = DetectData.rows(v, "exporters")
        return (e.reduce(0) { $0 + int($1["pointsSent"]) }, e.reduce(0) { $0 + int($1["failures"]) })
    }

    // MARK: Query building

    /// Query items for a fleet flow history request. Only parameters parseFlowQuery reads (since, limit, namespace, pod, peer,
    /// protocol, app, node); blanks are dropped and the limit is clamped to the server's 1...2000.
    public static func flowQuery(since: String, limit: Int, namespace: String = "", pod: String = "", peer: String = "") -> [URLQueryItem] {
        var q: [URLQueryItem] = []
        if !since.isEmpty { q.append(.init(name: "since", value: since)) }
        q.append(.init(name: "limit", value: String(min(max(limit, 1), 2000))))
        for (k, v) in [("namespace", namespace), ("pod", pod), ("peer", peer)] {
            let t = v.trimmingCharacters(in: .whitespaces)
            if !t.isEmpty { q.append(.init(name: k, value: t)) }
        }
        return q
    }
}
