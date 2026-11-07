// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation
import Network

/// One input of a mutation form. Kept UI-free so the catalog below is unit-testable.
public struct FormField: Identifiable, Sendable, Equatable {
    public enum Kind: Sendable, Equatable { case text, number, multiline, toggle, choice([String]) }
    public let key: String
    public let label: String
    public let kind: Kind
    public var initial: String
    public var help: String
    public var id: String { key }
    public init(_ key: String, _ label: String, _ kind: Kind = .text, initial: String = "", help: String = "") {
        self.key = key; self.label = label; self.kind = kind; self.initial = initial; self.help = help
    }
}

public typealias FormValues = [String: String]

/// A guarded mutation that is described by a form. `build` validates the values the same way the
/// server does and returns the spec to run through `MutationFlow`, or an explanation of what to fix.
public struct ControlAction: Identifiable, Sendable {
    public let id: String
    public let group: String
    public let title: String
    public let summary: String
    public let symbol: String
    /// Highest risk this action can reach, shown as a badge before the form opens.
    public let maxRisk: Risk
    public let fields: [FormField]
    public let build: @Sendable (_ client: NetraClient, _ values: FormValues) -> Result<MutationSpec, FormError>
}

public struct FormError: Error, Sendable, Equatable { public let message: String; public init(_ m: String) { message = m } }

// MARK: - parsing helpers (shared by the actions and the tests)

enum Form {
    static func str(_ v: FormValues, _ k: String) -> String { (v[k] ?? "").trimmingCharacters(in: .whitespacesAndNewlines) }
    static func int(_ v: FormValues, _ k: String) -> Int? { Int(str(v, k)) }
    static func flag(_ v: FormValues, _ k: String) -> Bool { str(v, k) == "true" }
    static func lines(_ v: FormValues, _ k: String) -> [String] {
        (v[k] ?? "").split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
    }
    static func list(_ v: FormValues, _ k: String) -> [String] {
        (v[k] ?? "").split(whereSeparator: { $0 == "," || $0.isNewline || $0 == " " }).map(String.init).filter { !$0.isEmpty }
    }
    static func json(_ o: Any) -> Data? { try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys]) }

    /// A canonical CIDR: the address has no bits set beyond the prefix (the server rejects `10.0.0.1/8`).
    static func isCanonicalCIDR(_ s: String) -> Bool {
        let p = s.split(separator: "/", omittingEmptySubsequences: false)
        guard p.count == 2, let bits = Int(p[1]), bits >= 0 else { return false }
        let bytes: [UInt8]
        if let a = IPv4Address(String(p[0])), bits <= 32 { bytes = Array(a.rawValue) }
        else if let a = IPv6Address(String(p[0])), bits <= 128 { bytes = Array(a.rawValue) }
        else { return false }
        for (i, b) in bytes.enumerated() {
            let keep = max(0, min(8, bits - i * 8))
            let mask = keep == 0 ? UInt8(0) : UInt8(truncatingIfNeeded: 0xFF << (8 - keep))
            if b & ~mask != 0 { return false }
        }
        return true
    }

    /// URLComponents leaves a literal `+` in a query value, and the Go server reads `+` as a space.
    /// Every `+` left in the query after URLComponents encoded it came from user text, so make it `%2B`.
    static func encodePlus(_ r: URLRequest) -> URLRequest {
        guard let u = r.url, var c = URLComponents(url: u, resolvingAgainstBaseURL: false), let q = c.percentEncodedQuery, q.contains("+") else { return r }
        c.percentEncodedQuery = q.replacingOccurrences(of: "+", with: "%2B")
        var out = r
        out.url = c.url ?? u
        return out
    }

    static func summarizePlan(_ v: JSONValue, risk: String?) -> String {
        let dry = v["dryRun"]
        var s = "Plan risk: \(risk ?? "unknown")."
        if case .bool(let b)? = dry?["passed"] { s += b ? " Dry-run passed." : " Dry-run FAILED\(dry?["error"]?.string.map { ": " + $0 } ?? "")." }
        return s
    }
}

extension ResultSummary {
    /// Go bulk-deny shape: {applied, failed, results:[{index, ok, error?}], note?}. Shared by deny-import,
    /// intel-apply and ai-destinations-deny. Returns nil when the body has no counts (not a bulk reply).
    public static func bulkApplied(_ v: JSONValue) -> ResultSummary? {
        let results = v["results"]?.controlItems ?? []
        guard let applied = v["applied"]?.controlInt ?? (results.isEmpty ? nil : results.filter { $0["ok"] == .bool(true) }.count) else { return nil }
        let failed = v["failed"]?.controlInt ?? results.filter { $0["ok"] == .bool(false) }.count
        var s = "Applied \(applied), failed \(failed)"
        if failed > 0 {
            let errs = results.filter { $0["ok"] != .bool(true) }.prefix(3).map { r in
                "entry \((r["index"]?.controlInt ?? 0) + 1): \(r["error"]?.string ?? "rejected")"
            }
            if !errs.isEmpty { s += " (" + errs.joined(separator: "; ") + (failed > errs.count ? "; +\(failed - errs.count) more" : "") + ")" }
        } else if applied == 0, let n = v["note"]?.string { s += ": \(n)" }
        return .init(s, isFailure: failed > 0)
    }
}

// MARK: - workload scope (shared by scope, conn-rate, netpol, default-deny)

public struct WorkloadScope: Sendable, Equatable {
    public var namespace = "", pod = "", workloadKind = "", workloadName = "", labels = ""

    public static let fields: [FormField] = [
        .init("namespace", "Namespace"), .init("pod", "Pod", help: "Exact pod name (optional)"),
        .init("workloadKind", "Workload kind", help: "e.g. Deployment (optional)"), .init("workloadName", "Workload name"),
        .init("labels", "Labels", help: "key=value, comma separated"),
    ]
    public init() {}
    public init(_ v: FormValues) {
        namespace = Form.str(v, "namespace"); pod = Form.str(v, "pod")
        workloadKind = Form.str(v, "workloadKind"); workloadName = Form.str(v, "workloadName"); labels = Form.str(v, "labels")
    }
    /// Parsed labels, or nil when one is malformed.
    var labelMap: [String: String]? {
        var m: [String: String] = [:]
        for part in labels.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) where !part.isEmpty {
            let kv = part.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard kv.count == 2, !kv[0].trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
            m[kv[0].trimmingCharacters(in: .whitespaces)] = kv[1].trimmingCharacters(in: .whitespaces)
        }
        return m
    }
    public var validationError: String? {
        if labelMap == nil { return "Labels must look like key=value, key2=value2" }
        if namespace.isEmpty && pod.isEmpty && workloadKind.isEmpty && workloadName.isEmpty && (labelMap ?? [:]).isEmpty {
            return "Choose at least one of namespace, pod, workload or labels: an empty scope is not allowed"
        }
        return nil
    }
    /// Only the fields the server knows; empties omitted so DisallowUnknownFields and omitempty both hold.
    public var json: [String: Any] {
        var o: [String: Any] = [:]
        if !namespace.isEmpty { o["namespace"] = namespace }
        if !pod.isEmpty { o["pod"] = pod }
        if !workloadKind.isEmpty { o["workloadKind"] = workloadKind }
        if !workloadName.isEmpty { o["workloadName"] = workloadName }
        if let l = labelMap, !l.isEmpty { o["labels"] = l }
        return o
    }
    public var label: String {
        [namespace, workloadName.isEmpty ? pod : workloadName].filter { !$0.isEmpty }.joined(separator: "/")
            .ifEmpty(labels.isEmpty ? "scope" : labels)
    }
}

private extension String { func ifEmpty(_ s: String) -> String { isEmpty ? s : self } }

extension ControlMutations {
    /// Read-only preview shared by the scoped actions: which pods the scope matches right now.
    static func scopePreview(_ c: NetraClient, _ scope: WorkloadScope) -> @Sendable () -> URLRequest {
        let body = Form.json(["scopes": [scope.json]])
        return { c.request("POST", "api/v1/ebpf/scope/preview", body: body) }
    }
    static func scopeSummary(_ v: JSONValue) -> String {
        let n = v["count"]?.controlInt ?? v["matched"]?.controlItems.count ?? 0
        let total = v["totalPods"]?.controlInt ?? 0
        return "Matches \(n) of \(total) pod(s) right now." + (n == 0 ? " Nothing matches this scope yet." : "")
    }
}

// MARK: - the catalog

extension ControlAction {
    private static let scopeAndNote = WorkloadScope.fields

    public static let all: [ControlAction] = nodeIsolation + shield + scope + connRate + netpol + defaultDeny + denyImport + intel + bulkCapture

    public static func find(_ id: String) -> ControlAction? { all.first { $0.id == id } }

    // MARK: Node isolation

    static let nodeIsolation: [ControlAction] = [
        ControlAction(
            id: "node-isolation-set", group: "Node isolation", title: "Isolate a node",
            summary: "Allow-only egress for one node. Shadow only counts what it would block; enforce drops everything else for a lease.",
            symbol: "lock.rectangle", maxRisk: .high,
            fields: [
                .init("node", "Node"),
                .init("mode", "Mode", .choice(["shadow", "enforce"]), initial: "shadow", help: "Shadow is observe-only and safe to try first"),
                .init("minutes", "Lease (minutes)", .number, initial: "15", help: "Enforce only, 1–60; the node fails open to observe when it ends"),
                .init("policyId", "Policy ID", help: "Optional label, up to 128 characters"),
                .init("rules", "Allowed destinations", .multiline, help: "One per line: CIDR [tcp|udp|any] [port or from-to]"),
                .init("exempt", "Exempt local ports", initial: "", help: "Blank keeps SSH (22) exempt. Comma list replaces it; 'none' removes every exemption"),
            ],
            build: { c, v in nodeIsolationSpec(c, v) }),
        ControlAction(
            id: "node-isolation-clear", group: "Node isolation", title: "Clear node isolation",
            summary: "Removes the node's isolation policy and restores its egress.", symbol: "lock.open", maxRisk: .low,
            fields: [.init("node", "Node")],
            build: { c, v in
                let node = Form.str(v, "node")
                guard !node.isEmpty, !node.contains(where: { "/ \t\r\n".contains($0) }) else { return .failure(.init("A valid node name is required")) }
                return .success(MutationSpec(
                    title: "Clear isolation on \(node)", risk: .low, expectedPhrase: "", leaseBound: false,
                    preview: { c.request("GET", "api/v1/ebpf/node-isolation") },
                    summarize: { r in
                        let on = r["items"]?.controlItems.contains { $0["node"]?.string == node } ?? false
                        return on ? "\(node) has an isolation policy; it will be removed." : "\(node) has no isolation policy; the server will answer 404."
                    },
                    execute: { _ in c.request("DELETE", "api/v1/ebpf/node-isolation/\(node)") }))
            }),
    ]

    static func nodeIsolationSpec(_ c: NetraClient, _ v: FormValues) -> Result<MutationSpec, FormError> {
        let node = Form.str(v, "node"), mode = Form.str(v, "mode")
        guard !node.isEmpty, node.utf8.count <= 253, !node.contains(where: { "/ \t\r\n".contains($0) }) else { return .failure(.init("A valid node name is required")) }
        guard ["shadow", "enforce"].contains(mode) else { return .failure(.init("Mode must be shadow or enforce")) }
        let policyId = Form.str(v, "policyId")
        guard policyId.utf8.count <= 128 else { return .failure(.init("Policy ID is too long (max 128)")) }
        var rules: [[String: Any]] = []
        for (i, line) in Form.lines(v, "rules").enumerated() {
            let p = line.split(separator: " ").map(String.init)
            guard let cidr = p.first, Form.isCanonicalCIDR(cidr) else { return .failure(.init("Rule \(i + 1): '\(p.first ?? "")' is not a canonical CIDR (host bits must be zero)")) }
            var r: [String: Any] = ["cidr": cidr]
            if p.count > 1 {
                let proto = p[1].lowercased()
                guard ["tcp", "udp", "any"].contains(proto) else { return .failure(.init("Rule \(i + 1): protocol must be tcp, udp or any")) }
                if proto != "any" { r["protocol"] = proto }
            }
            if p.count > 2 {
                let rng = p[2].split(separator: "-").map { Int($0) }
                guard rng.count <= 2, let from = rng[0] ?? nil, (1...65535).contains(from) else { return .failure(.init("Rule \(i + 1): invalid port")) }
                var to = from
                if rng.count == 2 { guard let t = rng[1], (from...65535).contains(t) else { return .failure(.init("Rule \(i + 1): invalid port range")) }; to = t }
                r["portFrom"] = from; if to != from { r["portTo"] = to }
            }
            guard p.count <= 3 else { return .failure(.init("Rule \(i + 1): too many fields")) }
            rules.append(r)
        }
        guard (1...64).contains(rules.count) else { return .failure(.init("Add 1 to 64 allowed destinations; an empty allow-list would cut all egress")) }
        var body: [String: Any] = ["mode": mode, "rules": rules]
        if !policyId.isEmpty { body["policyId"] = policyId }
        let ex = Form.str(v, "exempt")
        var dropsSSH = false
        if !ex.isEmpty {
            if ex.lowercased() == "none" { body["exemptLocalPorts"] = [Int](); dropsSSH = true }
            else {
                let ports = Form.list(v, "exempt").map { Int($0) }
                guard !ports.isEmpty else { return .failure(.init("Exempt ports: list at least one port, or type 'none' to remove every exemption")) }
                guard ports.count <= 16, ports.allSatisfy({ $0.map { (1...65535).contains($0) } ?? false }) else { return .failure(.init("Exempt ports must be up to 16 numbers, 1–65535")) }
                let set = Array(Set(ports.compactMap { $0 })).sorted()
                body["exemptLocalPorts"] = set; dropsSSH = !set.contains(22)
            }
        }
        var q: [URLQueryItem] = []
        let enforce = mode == "enforce"
        if enforce {
            guard let m = Form.int(v, "minutes"), (1...60).contains(m) else { return .failure(.init("Lease must be 1–60 minutes")) }
            q = [.init(name: "lease", value: "\(m)m")]
        }
        let data = Form.json(body)
        let ruleCount = rules.count, lacksSSH = dropsSSH, leaseQuery = q
        return .success(MutationSpec(
            title: "\(enforce ? "Enforce" : "Shadow") node isolation on \(node)", risk: enforce ? .high : .low,
            expectedPhrase: enforce ? "isolate \(node)" : "", leaseBound: enforce,
            preview: { c.request("GET", "api/v1/ebpf/node-isolation") },
            summarize: { r in
                let have = r["items"]?.controlItems.first { $0["node"]?.string == node }
                var s = have.map { "\(node) already has a \($0["mode"]?.string ?? "?") policy; this replaces it." } ?? "\(node) has no isolation policy yet."
                s += " \(ruleCount) allowed destination(s)."
                s += enforce ? " Everything else egressing the node is dropped until the lease ends." : " Shadow mode only counts what would be blocked."
                if enforce && lacksSSH { s += " WARNING: SSH (22) is not exempt, so you could lose access to this node." }
                return s
            },
            execute: { _ in c.request("PUT", "api/v1/ebpf/node-isolation/\(node)", query: leaseQuery, body: data) }))
    }

    // MARK: Shield

    static let shield: [ControlAction] = [
        ControlAction(
            id: "shield-set", group: "Shield", title: "Set shield (flood protection)",
            summary: "Per-class packet-rate thresholds for protected addresses. Audit counts; enforce drops.", symbol: "shield.lefthalf.filled", maxRisk: .high,
            fields: [
                .init("mode", "Mode", .choice(["off", "audit", "enforce"]), initial: "audit"),
                .init("protectAll", "Protect all addresses", .toggle),
                .init("ipv4", "Protected IPv4", help: "Exact addresses, comma separated"),
                .init("ipv6", "Protected IPv6", help: "Exact addresses, comma separated"),
                .init("synPps", "SYN pps", .number, initial: "0", help: "0 disables the class; max 10,000,000"),
                .init("udpPps", "UDP pps", .number, initial: "0"), .init("icmpPps", "ICMP pps", .number, initial: "0"),
                .init("otherPps", "Other pps", .number, initial: "0"), .init("burst", "Burst seconds", .number, initial: "0", help: "0–60"),
            ],
            build: { c, v in
                let mode = Form.str(v, "mode")
                guard ["off", "audit", "enforce"].contains(mode) else { return .failure(.init("Mode must be off, audit or enforce")) }
                let v4 = Form.list(v, "ipv4"), v6 = Form.list(v, "ipv6")
                if let bad = v4.first(where: { IPv4Address($0) == nil }) { return .failure(.init("Protected IPv4 entries must be exact IPv4 addresses: \(bad)")) }
                if let bad = v6.first(where: { IPv6Address($0) == nil }) { return .failure(.init("Protected IPv6 entries must be exact IPv6 addresses: \(bad)")) }
                var body: [String: Any] = ["mode": mode]
                if Form.flag(v, "protectAll") { body["protectAll"] = true }
                if !v4.isEmpty { body["protectedIpv4"] = v4 }
                if !v6.isEmpty { body["protectedIpv6"] = v6 }
                for (k, wire) in [("synPps", "synPps"), ("udpPps", "udpPps"), ("icmpPps", "icmpPps"), ("otherPps", "otherPps")] {
                    let n = Form.int(v, k) ?? 0
                    guard (0...10_000_000).contains(n) else { return .failure(.init("\(wire) must be 0–10,000,000")) }
                    if n > 0 { body[wire] = n }
                }
                let burst = Form.int(v, "burst") ?? 0
                guard (0...60).contains(burst) else { return .failure(.init("Burst seconds must be 0–60")) }
                if burst > 0 { body["burstSeconds"] = burst }
                if mode != "off", !Form.flag(v, "protectAll"), v4.isEmpty, v6.isEmpty { return .failure(.init("Protect all addresses, or list at least one")) }
                let data = Form.json(body), enforce = mode == "enforce"
                return .success(MutationSpec(
                    title: "Set shield to \(mode)", risk: enforce ? .high : .low, expectedPhrase: enforce ? "shield enforce" : "", leaseBound: false,
                    // GET /ebpf/shield is the drop diagnostics, not the config; the stored shield config is in /ebpf/config.
                    preview: { c.request("GET", "api/v1/ebpf/config") },
                    summarize: { r in
                        let cur = r["shield"]?["mode"]?.string ?? "off (never configured)"
                        return "Shield is currently \(cur); it will become \(mode)." + (enforce ? " Enforce drops packets over the thresholds for protected addresses." : "")
                    },
                    execute: { _ in c.request("PUT", "api/v1/ebpf/shield", body: data) }))
            }),
    ]

    // MARK: Observation scope

    static let scope: [ControlAction] = [
        ControlAction(
            id: "scope-set", group: "Scope", title: "Set workload scope",
            summary: "Limit eBPF observation to selected workloads, or return to all workloads.", symbol: "scope", maxRisk: .medium,
            fields: [.init("mode", "Mode", .choice(["all", "selected"]), initial: "selected")] + WorkloadScope.fields,
            build: { c, v in
                let mode = Form.str(v, "mode")
                guard ["all", "selected"].contains(mode) else { return .failure(.init("Mode must be all or selected")) }
                if mode == "all" {
                    let data = Form.json(["mode": "all", "scopes": [Any]()])
                    return .success(MutationSpec(
                        title: "Observe all workloads", risk: .low, expectedPhrase: "", leaseBound: false,
                        preview: { c.request("GET", "api/v1/ebpf/config") },
                        summarize: { _ in "Removes the workload filter; every workload is observed again." },
                        execute: { _ in c.request("PUT", "api/v1/ebpf/scope", body: data) }))
                }
                let sc = WorkloadScope(v)
                if let e = sc.validationError { return .failure(.init(e)) }
                let data = Form.json(["mode": "selected", "scopes": [sc.json]])
                return .success(MutationSpec(
                    title: "Observe only \(sc.label)", risk: .medium, expectedPhrase: "", leaseBound: false,
                    preview: ControlMutations.scopePreview(c, sc),
                    summarize: { r in ControlMutations.scopeSummary(r) + " Everything else stops being observed." },
                    execute: { _ in c.request("PUT", "api/v1/ebpf/scope", body: data) }))
            }),
    ]

    // MARK: Per-workload connection rate

    static let connRate: [ControlAction] = [
        ControlAction(
            id: "conn-rate-add", group: "Connection rate", title: "Limit new connections",
            summary: "Cap new TCP connection attempts per second for matching workloads. Applies only while an enforce lease is active.",
            symbol: "speedometer", maxRisk: .medium,
            fields: WorkloadScope.fields + [.init("perSecond", "Per second", .number, initial: "100")],
            build: { c, v in
                let sc = WorkloadScope(v)
                if let e = sc.validationError { return .failure(.init(e)) }
                guard let n = Form.int(v, "perSecond"), (1...Int(UInt32.max)).contains(n) else { return .failure(.init("Per-second limit must be greater than zero")) }
                let data = Form.json(["selector": sc.json, "perSecond": n])
                return .success(MutationSpec(
                    title: "Limit \(sc.label) to \(n) connects/s", risk: .medium, expectedPhrase: "", leaseBound: true,
                    preview: ControlMutations.scopePreview(c, sc),
                    summarize: { r in ControlMutations.scopeSummary(r) + " New connections above \(n)/s are refused while enforce is leased." },
                    execute: { _ in c.request("POST", "api/v1/ebpf/conn-rate-limit", body: data) }))
            }),
        ControlAction(
            id: "conn-rate-delete", group: "Connection rate", title: "Remove a connection limit",
            summary: "Deletes one limit by its ID.", symbol: "speedometer", maxRisk: .low,
            fields: [.init("id", "Limit ID")],
            build: { c, v in
                let id = Form.str(v, "id")
                guard !id.isEmpty, !id.contains("/") else { return .failure(.init("A limit ID is required")) }
                return .success(MutationSpec(
                    title: "Remove connection limit \(id)", risk: .low, expectedPhrase: "", leaseBound: false,
                    preview: { c.request("GET", "api/v1/ebpf/config") },
                    summarize: { r in
                        let have = (r["connRateLimits"]?.controlItems ?? []).contains { $0["id"]?.string == id }   // omitempty: absent means none
                        return !have ? "No limit with ID \(id) is listed; the server will answer 404." : "Removes limit \(id)."
                    },
                    execute: { _ in c.request("DELETE", "api/v1/ebpf/conn-rate-limit/\(id)") }))
            }),
    ]

    // MARK: Network policy rules and toggle

    static let netpol: [ControlAction] = [
        ControlAction(
            id: "netpol-rule-add", group: "Network policy", title: "Add a workload allow/deny rule",
            summary: "Per-workload peer/port rule. Deny can cut a workload's traffic, so it needs a typed confirmation.",
            symbol: "point.3.filled.connected.trianglepath.dotted", maxRisk: .high,
            fields: WorkloadScope.fields + [
                .init("action", "Action", .choice(["allow", "deny"]), initial: "allow"),
                .init("peer", "Peer IPv4", help: "Exact address, or blank for a port-only rule"),
                .init("port", "Port", .number, initial: "0", help: "0 = any; required when no peer"),
                .init("protocol", "Protocol", .choice(["ANY", "TCP", "UDP"]), initial: "ANY"),
                .init("direction", "Direction", .choice(["both", "ingress", "egress"]), initial: "both"),
            ],
            build: { c, v in
                let sc = WorkloadScope(v)
                if let e = sc.validationError { return .failure(.init(e)) }
                let action = Form.str(v, "action"), peer = Form.str(v, "peer"), port = Form.int(v, "port") ?? 0
                guard ["allow", "deny"].contains(action) else { return .failure(.init("Action must be allow or deny")) }
                guard (0...65535).contains(port) else { return .failure(.init("Port must be 0–65535")) }
                if peer.isEmpty { if port == 0 { return .failure(.init("A peer IPv4 or an exact port is required")) } }
                else if IPv4Address(peer) == nil { return .failure(.init("Peer must be an exact IPv4 address, or blank for a port-only rule")) }
                var body: [String: Any] = ["selector": sc.json, "action": action, "protocol": Form.str(v, "protocol").uppercased(), "direction": Form.str(v, "direction")]
                if !peer.isEmpty { body["peerIpv4"] = peer }
                if port > 0 { body["port"] = port }
                let data = Form.json(body), deny = action == "deny"
                let what = [peer.isEmpty ? "any peer" : peer, port > 0 ? "port \(port)" : nil].compactMap { $0 }.joined(separator: " ")
                return .success(MutationSpec(
                    title: "\(action.capitalized) \(what) for \(sc.label)", risk: deny ? .high : .medium,
                    expectedPhrase: deny ? "deny \(sc.label)" : "", leaseBound: true,
                    preview: ControlMutations.scopePreview(c, sc),
                    summarize: { r in ControlMutations.scopeSummary(r) + (deny ? " Matching traffic is dropped while enforce is leased." : "") },
                    execute: { _ in c.request("POST", "api/v1/ebpf/netpol/rules", body: data) }))
            }),
        ControlAction(
            id: "netpol-rule-delete", group: "Network policy", title: "Remove a workload rule",
            summary: "Deletes one network policy rule by ID.", symbol: "minus.circle", maxRisk: .low,
            fields: [.init("id", "Rule ID")],
            build: { c, v in
                let id = Form.str(v, "id")
                guard !id.isEmpty, !id.contains("/") else { return .failure(.init("A rule ID is required")) }
                return .success(MutationSpec(
                    title: "Remove network policy rule \(id)", risk: .low, expectedPhrase: "", leaseBound: false,
                    preview: { c.request("GET", "api/v1/ebpf/config") },
                    summarize: { r in
                        let have = (r["netPolRules"]?.controlItems ?? []).contains { $0["id"]?.string == id }   // omitempty: absent means none
                        return !have ? "No rule with ID \(id) is listed; the server will answer 404." : "Removes rule \(id)."
                    },
                    execute: { _ in c.request("DELETE", "api/v1/ebpf/netpol/rules/\(id)") }))
            }),
        ControlAction(
            id: "netpol-toggle", group: "Network policy", title: "Enable or disable the engine",
            summary: "Turns the per-workload network policy engine on or off. Rules only take effect while it is on.",
            symbol: "switch.2", maxRisk: .medium,
            fields: [.init("version", "Engine", .choice(["v1", "v2"]), initial: "v2"), .init("enabled", "Enabled", .toggle, initial: "true")],
            build: { c, v in
                let ver = Form.str(v, "version"), on = Form.flag(v, "enabled")
                guard ["v1", "v2"].contains(ver) else { return .failure(.init("Engine must be v1 or v2")) }
                let data = Form.json(["enabled": on])
                let path = ver == "v2" ? "api/v1/ebpf/netpol/v2/config" : "api/v1/ebpf/netpol/config"
                return .success(MutationSpec(
                    title: "\(on ? "Enable" : "Disable") network policy \(ver)", risk: on ? .medium : .low, expectedPhrase: "", leaseBound: on,
                    preview: { c.request("GET", "api/v1/ebpf/config") },
                    summarize: { _ in on ? "Rules for this engine start applying under the enforce lease." : "Rules for this engine stop applying." },
                    execute: { _ in c.request("PUT", path, body: data) }))
            }),
    ]

    // MARK: Default-deny (plan token)

    static let defaultDeny: [ControlAction] = [
        ControlAction(
            id: "default-deny", group: "Network policy", title: "Default-deny a workload set",
            summary: "Plan first: the server counts matching workloads and whether allow rules cover them. Without allow rules this is an outage, and is rated critical.",
            symbol: "nosign", maxRisk: .critical,
            fields: WorkloadScope.fields + [
                .init("enabled", "Enable default-deny", .toggle, initial: "true"),
                .init("minutes", "Lease (minutes)", .number, initial: "5", help: "Enable only, 1–60"),
                .init("allowNoRules", "Allow with zero covering allow rules", .toggle, help: "Overrides the server's refusal. Expect an outage."),
            ],
            build: { c, v in
                let sc = WorkloadScope(v)
                if let e = sc.validationError { return .failure(.init(e)) }
                let on = Form.flag(v, "enabled")
                var body: [String: Any] = ["selector": sc.json, "enabled": on]
                if on {
                    guard let m = Form.int(v, "minutes"), (1...60).contains(m) else { return .failure(.init("Lease must be 1–60 minutes")) }
                    body["lease"] = "\(m)m"
                }
                // The server binds the plan token to these exact bytes, so plan and apply share one buffer.
                guard let data = Form.json(body) else { return .failure(.init("Could not encode the request")) }
                let q: [URLQueryItem] = Form.flag(v, "allowNoRules") ? [.init(name: "allowNoRules", value: "true")] : []   // immutable: captured by the closures below
                return .success(MutationSpec(
                    title: "\(on ? "Enable" : "Disable") default-deny for \(sc.label)", risk: on ? .medium : .low,
                    expectedPhrase: "default-deny \(sc.label)", leaseBound: on,
                    preview: { c.request("POST", "api/v1/ebpf/netpol/default-deny/plan", query: q, body: data) },
                    summarize: { r in
                        let risk = r["risk"]?.string ?? "unknown"
                        var s = "Plan risk: \(risk). Matches \(r["matchedWorkloads"]?.controlInt ?? 0) workload(s); \(r["workloadsWithAllowRule"]?.controlInt ?? 0) covered by an allow rule."
                        if r["receipt"]?["token"]?.string == nil { s += " No plan token was issued, so apply will be refused." }
                        return s
                    },
                    executeWithPreview: { preview, _ in
                        var req = c.request("PUT", "api/v1/ebpf/netpol/default-deny", body: data)
                        if let t = preview["receipt"]?["token"]?.string { req.setValue(t, forHTTPHeaderField: "X-Netra-Plan-Token") }
                        return req
                    },
                    riskFromPreview: { Risk(serverValue: $0["risk"]?.string) },
                    execute: { _ in c.request("PUT", "api/v1/ebpf/netpol/default-deny", body: data) }))
            }),
    ]

    // MARK: Deny import

    struct DenyEntry: Equatable { let type: String; let value: String; let direction: String? }

    /// One entry per line: `value`, or `type value [direction]`. Bare values are classified as ip, cidr or dns.
    static func parseDenyImport(_ lines: [String]) -> (entries: [DenyEntry], error: String?) {
        var out: [DenyEntry] = []
        for (i, line) in lines.enumerated() {
            let p = line.split(whereSeparator: { $0 == " " || $0 == "," || $0 == "\t" }).map(String.init)
            var type: String, value: String, dir: String?
            if p.count >= 2, ["ip", "cidr", "dns", "sni"].contains(p[0].lowercased()) { type = p[0].lowercased(); value = p[1]; dir = p.count > 2 ? p[2].lowercased() : nil }
            else if p.count >= 1 {
                value = p[0]; dir = p.count > 1 ? p[1].lowercased() : nil
                type = RuleDraft.isIP(value) ? "ip" : RuleDraft.isCIDR(value) ? "cidr" : "dns"
            } else { continue }
            if let d = dir, !["egress", "ingress", "both"].contains(d) { return (out, "Line \(i + 1): direction must be egress, ingress or both") }
            if dir != nil, type == "dns" || type == "sni" { return (out, "Line \(i + 1): \(type) entries have no direction") }
            switch type {
            case "ip": if !RuleDraft.isIP(value) { return (out, "Line \(i + 1): '\(value)' is not an IP address") }
            case "cidr": if !RuleDraft.isCIDR(value) { return (out, "Line \(i + 1): '\(value)' is not a CIDR") }
            default: if !RuleDraft.isDNSName(value) { return (out, "Line \(i + 1): '\(value)' is not a valid DNS name") }
            }
            out.append(.init(type: type, value: value, direction: dir))
        }
        return (out, nil)
    }

    static let denyImport: [ControlAction] = [
        ControlAction(
            id: "deny-import", group: "Rules", title: "Import a deny list",
            summary: "Bulk-add IP, CIDR, DNS and SNI denies. Partial success is reported per entry. Active only while enforce is leased.",
            symbol: "square.and.arrow.down.on.square", maxRisk: .high,
            fields: [.init("entries", "Entries", .multiline, help: "One per line: value, or type value [direction]. Direction (ip and cidr only) defaults to egress. Max 1000. # starts a comment.")],
            build: { c, v in
                let (entries, err) = parseDenyImport(Form.lines(v, "entries"))
                if let err { return .failure(.init(err)) }
                guard !entries.isEmpty else { return .failure(.init("Add at least one entry")) }
                guard entries.count <= 1000 else { return .failure(.init("At most 1000 entries per import (got \(entries.count))")) }
                let list: [[String: Any]] = entries.map { e in var o: [String: Any] = ["type": e.type, "value": e.value]; if let d = e.direction { o["direction"] = d }; return o }
                let data = Form.json(["entries": list])
                let by = Dictionary(grouping: entries, by: \.type).mapValues(\.count)
                let breakdown = ["ip", "cidr", "dns", "sni"].compactMap { k in by[k].map { "\($0) \(k)" } }.joined(separator: ", ")
                return .success(MutationSpec(
                    title: "Import \(entries.count) deny entr\(entries.count == 1 ? "y" : "ies")", risk: .high,
                    expectedPhrase: "import \(entries.count) denies", leaseBound: true,
                    preview: { c.request("GET", "api/v1/ebpf/rules") },
                    summarize: { r in
                        let n = r["items"]?.controlItems.count ?? r.controlItems.count
                        return "Adds \(breakdown) to the \(n) existing rule(s). Every entry was validated locally; the server reports any it still rejects."
                    },
                    resultSummary: ResultSummary.bulkApplied,
                    execute: { _ in c.request("POST", "api/v1/ebpf/deny/import", body: data) }))
            }),
    ]

    // MARK: Threat-intel feed

    /// GET /intel/feed answers {feed: {revision, count, ...}, entries: [...]}.
    static func feedRevision(_ r: JSONValue) -> String { (r["feed"]?["revision"] ?? r["revision"])?.summary ?? "?" }
    static func feedEntryCount(_ r: JSONValue) -> Int { r["feed"]?["count"]?.controlInt ?? r["entries"]?.controlItems.count ?? 0 }

    static let intel: [ControlAction] = [
        ControlAction(
            id: "intel-feed-put", group: "Threat intel", title: "Replace the intel feed",
            summary: "Stores a feed. It applies nothing: applying is a separate, leased, high-risk step.", symbol: "tray.and.arrow.down", maxRisk: .medium,
            fields: [
                .init("feed", "Feed", .multiline, help: "The feed text exactly as the server parses it"),
                .init("source", "Source", help: "Optional label (defaults to 'operator')"),
                .init("note", "Note"), .init("ttlHours", "Expire after (hours)", .number, initial: "0", help: "0 = never, max 720"),
            ],
            build: { c, v in
                let text = v["feed"] ?? ""
                guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return .failure(.init("Paste the feed text")) }
                guard text.utf8.count <= 1 << 20 else { return .failure(.init("The feed is larger than 1 MiB")) }
                let ttl = Form.int(v, "ttlHours") ?? 0
                guard (0...720).contains(ttl) else { return .failure(.init("Expiry must be 0–720 hours")) }
                let note = Form.str(v, "note"), source = Form.str(v, "source")
                guard note.utf8.count <= 1024, source.utf8.count <= 512 else { return .failure(.init("Source or note is too long")) }
                guard source.unicodeScalars.allSatisfy({ $0.isASCII && $0.value >= 0x20 && $0.value != 0x7F }) else {
                    return .failure(.init("Source is sent as an HTTP header: use printable ASCII only"))
                }
                let data = Data(text.utf8)
                var qv: [URLQueryItem] = []
                if !note.isEmpty { qv.append(.init(name: "note", value: note)) }
                if ttl > 0 { qv.append(.init(name: "ttl", value: "\(ttl)h")) }
                let q = qv
                return .success(MutationSpec(
                    title: "Replace the intel feed", risk: .medium, expectedPhrase: "", leaseBound: false,
                    preview: { var r = c.request("POST", "api/v1/intel/preview", body: data); r.setValue("text/plain", forHTTPHeaderField: "Content-Type"); return r },
                    summarize: { r in
                        let n = r["preview"]?["entries"]?.controlItems.count ?? 0
                        let skipped = r["preview"]?["skipped"]?.controlItems.count ?? 0
                        return "The server parsed \(n) entr\(n == 1 ? "y" : "ies")" + (skipped > 0 ? " and skipped \(skipped) line(s)" : "")
                            + ". Storing it replaces the active feed but applies no denies."
                    },
                    execute: { _ in
                        var r = Form.encodePlus(c.request("PUT", "api/v1/intel/feed", query: q, body: data))
                        r.setValue("text/plain", forHTTPHeaderField: "Content-Type")
                        if !source.isEmpty { r.setValue(source, forHTTPHeaderField: "X-Netra-Intel-Source") }
                        return r
                    }))
            }),
        ControlAction(
            id: "intel-feed-clear", group: "Threat intel", title: "Clear the intel feed",
            summary: "Empties the stored feed. Denies that were already applied are not removed.", symbol: "trash", maxRisk: .medium,
            fields: [],
            build: { c, _ in
                .success(MutationSpec(
                    title: "Clear the intel feed", risk: .medium, expectedPhrase: "", leaseBound: false,
                    preview: { c.request("GET", "api/v1/intel/feed") },
                    summarize: { r in "Clears feed revision \(ControlAction.feedRevision(r)) (\(ControlAction.feedEntryCount(r)) entr\(ControlAction.feedEntryCount(r) == 1 ? "y" : "ies")). Already-applied denies stay." },
                    execute: { _ in c.request("DELETE", "api/v1/intel/feed") }))
            }),
        ControlAction(
            id: "intel-feed-rollback", group: "Threat intel", title: "Roll back the intel feed",
            summary: "Restores an earlier feed revision. Does not apply it.", symbol: "arrow.uturn.backward", maxRisk: .medium,
            fields: [.init("revision", "Revision", .number)],
            build: { c, v in
                guard let rev = Form.int(v, "revision"), rev > 0 else { return .failure(.init("Revision must be a positive integer")) }
                return .success(MutationSpec(
                    title: "Roll back the intel feed to revision \(rev)", risk: .medium, expectedPhrase: "", leaseBound: false,
                    preview: { c.request("GET", "api/v1/intel/feed") },
                    summarize: { r in "Current feed is revision \(ControlAction.feedRevision(r)); this restores revision \(rev) (the server answers 400 if that revision is not in its history)." },
                    execute: { _ in c.request("POST", "api/v1/intel/rollback/\(rev)") }))
            }),
        ControlAction(
            id: "intel-apply", group: "Threat intel", title: "Apply the intel feed as denies",
            summary: "Turns feed entries into deny rules. Needs enforce mode with an active lease; fails open when it ends.",
            symbol: "bolt.shield", maxRisk: .high,
            fields: [.init("matchedOnly", "Only entries seen in live traffic", .toggle, initial: "true", help: "Applies just the feed entries that matched real flows")],
            build: { c, v in
                let matched = Form.flag(v, "matchedOnly")
                let q: [URLQueryItem] = matched ? [.init(name: "matchedOnly", value: "true")] : []
                return .success(MutationSpec(
                    title: matched ? "Apply matched intel entries" : "Apply the whole intel feed", risk: .high,
                    expectedPhrase: matched ? "apply matched intel" : "apply intel feed", leaseBound: true,
                    preview: { c.request("GET", "api/v1/intel/feed") },
                    summarize: { r in
                        let n = r["entries"]?.controlItems.count ?? r["feed"]?["entries"]?.controlItems.count
                        if n == 0 { return "The active feed is empty: the server answers 400 and nothing is applied." }
                        return (n.map { "The feed has \($0) entr\($0 == 1 ? "y" : "ies"). " } ?? "")
                            + (matched ? "Only entries that matched live traffic become denies." : "Every entry becomes a deny rule.")
                            + " Requires enforce mode with an active lease."
                    },
                    resultSummary: ResultSummary.bulkApplied,
                    execute: { confirm in c.request("POST", "api/v1/intel/apply", query: q, confirmRisk: confirm) }))
            }),
    ]

    // MARK: Bulk capture

    static let bulkCapture: [ControlAction] = [
        ControlAction(
            id: "capture-bulk", group: "Capture", title: "Start capture on several nodes",
            summary: "Same filter on each node. The server stops at 25 captures cluster-wide and reports each node.", symbol: "record.circle.fill", maxRisk: .medium,
            fields: [
                .init("nodes", "Nodes", .multiline, help: "One per line or comma separated"),
                .init("backend", "Backend", .choice(["ebpf", "afpacket"]), initial: "ebpf"),
                .init("proto", "Protocol", .choice(["", "tcp", "udp", "icmp"])),
                .init("host", "Host"), .init("port", "Port", .number, initial: "0"),
                .init("duration", "Duration (s)", .number, initial: "60", help: "1–300"),
            ],
            build: { c, v in
                let nodes = Array(Set(Form.list(v, "nodes").filter { !$0.isEmpty })).sorted()
                guard !nodes.isEmpty else { return .failure(.init("Add at least one node")) }
                var p = ControlMutations.CaptureParams()
                p.node = nodes[0]; p.backend = Form.str(v, "backend"); p.proto = Form.str(v, "proto")
                p.host = Form.str(v, "host"); p.port = Form.int(v, "port") ?? 0; p.durationSeconds = Form.int(v, "duration") ?? 0
                if let e = p.validationError { return .failure(.init(e)) }
                guard var obj = (p.body.flatMap { try? JSONSerialization.jsonObject(with: $0) }) as? [String: Any] else { return .failure(.init("Could not encode the request")) }
                obj["nodes"] = nodes
                let data = Form.json(obj)
                return .success(MutationSpec(
                    title: "Start capture on \(nodes.count) node(s)", risk: .medium, expectedPhrase: "", leaseBound: false,
                    preview: { c.request("GET", "api/v1/capture/status") },
                    summarize: { r in
                        let active = r["active"]?.controlItems.count ?? 0
                        let over = active + nodes.count > 25
                        return "\(active) capture(s) active cluster-wide; this asks for \(nodes.count) more (max 25)."
                            + (over ? " Some nodes will be refused; the result lists each one." : "")
                    },
                    execute: { _ in c.request("POST", "api/v1/capture/bulk", body: data) }))
            }),
    ]
}
