// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation
import Network

public enum RuleKind: String, CaseIterable, Identifiable, Sendable {
    case ip, cidr, port, uid, dns, sni, process, capability, exeHash, synDrop, synDropCIDR, rate
    public var id: String { rawValue }
    public var title: String {
        switch self {
        case .ip: "IP address"
        case .cidr: "CIDR"
        case .port: "Port"
        case .uid: "User ID"
        case .dns: "DNS name"
        case .sni: "TLS SNI"
        case .process: "Process (comm)"
        case .capability: "Capability"
        case .exeHash: "Executable SHA-256"
        case .synDrop: "SYN drop (IP)"
        case .synDropCIDR: "SYN drop (CIDR)"
        case .rate: "Rate limit (IP)"
        }
    }
    /// Kinds the server also exposes as allow-lists (exempt traffic from deny rules).
    public var supportsAllow: Bool { [.ip, .cidr, .port, .uid, .process].contains(self) }
    public var hasDirection: Bool { [.ip, .cidr, .port, .synDrop, .synDropCIDR].contains(self) }
    /// Kinds /ebpf/deny/preview can replay against observed traffic.
    public var hasDryRun: Bool { [.ip, .cidr, .port, .dns, .sni, .process].contains(self) }
}

public enum RuleAction: String, CaseIterable, Sendable { case deny, allow }

/// One add-or-remove of a fast-path rule. Validation mirrors the controller's normalizers so the
/// form explains a rejection before anything is sent; the server stays authoritative.
public struct RuleDraft: Sendable, Equatable {
    public var kind: RuleKind = .ip
    public var action: RuleAction = .deny
    public var removing = false
    public var value = ""              // ip / cidr / uid / dns / sni / process / capability / hash
    public var direction = "egress"    // egress | ingress | both (SYN drop: egress | ingress)
    public var proto = "ANY"           // TCP | UDP | ANY
    public var port = 0
    public var pps = 0
    public var bps = 0
    public init() {}

    public var v: String { value.trimmingCharacters(in: .whitespaces) }

    static func isIP(_ s: String) -> Bool { IPv4Address(s) != nil || IPv6Address(s) != nil }

    static func isCIDR(_ s: String) -> Bool {
        let parts = s.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let bits = Int(parts[1]) else { return false }
        let a = String(parts[0])
        return (IPv4Address(a) != nil && (0...32).contains(bits)) || (IPv6Address(a) != nil && (0...128).contains(bits))
    }

    static func isDNSName(_ raw: String) -> Bool {
        var s = raw.lowercased(); if s.hasSuffix(".") { s.removeLast() }
        guard !s.isEmpty, s.utf8.count <= 95 else { return false }
        return s.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            !label.isEmpty && label.utf8.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-")
                && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
        }
    }

    public var validationError: String? {
        if action == .allow && !kind.supportsAllow { return "\(kind.title) has no allow-list" }
        switch kind {
        case .ip, .synDrop: if !Self.isIP(v) { return "A valid IPv4 or IPv6 address is required" }
        case .cidr, .synDropCIDR: if !Self.isCIDR(v) { return "A valid IPv4 or IPv6 CIDR is required (e.g. 10.0.0.0/8)" }
        case .rate: if !Self.isIP(v) { return "Rate limiting needs an exact IPv4 or IPv6 destination" }
        case .port: if !(1...65535).contains(port) { return "Port must be 1–65535" }
        case .uid: if UInt32(v) == nil { return "A numeric user ID is required" }
        case .dns, .sni: if !Self.isDNSName(v) { return "A valid DNS name is required (letters, digits, - and _)" }
        case .process: if v.isEmpty || v.utf8.count > 15 { return "Process name must be 1–15 bytes (Linux comm)" }
        case .capability: if !["CAP_NET_ADMIN", "CAP_NET_RAW"].contains(v.uppercased()) { return "Capability must be CAP_NET_ADMIN or CAP_NET_RAW" }
        case .exeHash: if v.count != 64 || !v.lowercased().allSatisfy({ $0.isHexDigit }) { return "A 64-character hex SHA-256 digest is required" }
        }
        if kind.hasDirection {
            let ok = (kind == .synDrop || kind == .synDropCIDR) ? ["egress", "ingress"] : ["egress", "ingress", "both"]
            if !ok.contains(direction) { return "Direction must be \(ok.joined(separator: ", "))" }
        }
        if kind == .port, !["TCP", "UDP", "ANY"].contains(proto.uppercased()) { return "Protocol must be TCP, UDP or ANY" }
        if kind == .rate {
            if pps > 10_000_000 || bps < 0 || pps < 0 { return "pps must be between 1 and 10000000" }
            if pps == 0 && bps == 0 && !removing { return "Set pps, bps or both" }
        }
        return nil
    }

    // MARK: Risk and wording

    /// Deny rules and anything that can lock traffic out are high risk; allow-lists and removals are not.
    public var risk: Risk {
        if removing { return .medium }
        if action == .allow || kind == .rate { return .medium }
        return .high
    }
    public var display: String { kind == .port ? "\(proto.uppercased())/\(port)" : v }
    public var title: String {
        let verb = removing ? "Remove" : (kind == .rate ? "Rate-limit" : action == .allow ? "Allow" : "Deny")
        return "\(verb) \(kind.title.lowercased()) \(display)"
    }
    public var expectedPhrase: String { "\(removing ? "remove" : kind == .rate ? "limit" : "deny") \(display)" }

    // MARK: Requests

    private func json(_ d: [String: Any]) -> Data? { try? JSONSerialization.data(withJSONObject: d) }
    private var al: String { action == .allow ? "allow-" : "" }

    private var body: [String: Any] {
        switch kind {
        case .ip: action == .allow ? ["ip": v] : ["ip": v, "direction": direction]   // allow takes only {ip}
        case .cidr: ["cidr": v, "direction": direction]
        case .port: ["protocol": proto.uppercased(), "port": port, "direction": direction]
        case .uid: ["uid": UInt32(v) ?? 0]
        case .dns, .sni, .process: ["name": v]
        case .capability: ["name": v.uppercased()]
        case .exeHash: ["hash": v.lowercased()]
        case .synDrop: ["address": v, "direction": direction]
        case .synDropCIDR: ["cidr": v, "direction": direction]
        case .rate: ["destination": v, "pps": pps, "bps": bps]
        }
    }

    private var addPath: (method: String, path: String) {
        switch kind {
        case .ip: ("POST", action == .allow ? "allow" : "deny")
        case .cidr: ("POST", "\(al)cidr")
        case .port: ("POST", "\(al)port")
        case .uid: ("POST", "\(al)uid")
        case .process: ("POST", "\(al)process")
        case .dns: ("POST", "dns")
        case .sni: ("POST", "sni")
        case .capability: ("POST", "capability")
        case .exeHash: ("POST", "exehash-deny")
        case .synDrop: ("POST", "syn-drop")
        case .synDropCIDR: ("POST", "syn-drop-cidr")
        case .rate: ("PUT", "rate")
        }
    }

    public func mutationRequest(_ c: NetraClient) -> URLRequest {
        let base = "api/v1/ebpf/"
        let (m, p) = addPath
        guard removing else { return c.request(m, base + p, body: json(body)) }
        switch kind {
        case .ip: return c.request("DELETE", base + (action == .allow ? "allow/" : "deny/") + v)
        case .uid: return c.request("DELETE", base + (action == .allow ? "allow-uid/" : "uid/") + v)
        case .rate: return c.request("DELETE", base + "rate/" + v)
        default: return c.request("POST", base + p + "/delete", body: json(body))
        }
    }

    /// A dry run where the server has one (replays the proposal against observed traffic);
    /// otherwise a read of the current rules, so the sheet can say what exists.
    public func previewRequest(_ c: NetraClient) -> URLRequest {
        guard !removing, action == .deny, kind.hasDryRun else { return c.request("GET", "api/v1/ebpf/rules") }
        var d: [String: Any] = ["kind": kind.rawValue, "value": kind == .port ? String(port) : v]
        if kind.hasDirection { d["direction"] = direction }
        if kind == .port { d["port"] = port; d["protocol"] = proto.uppercased() }
        return c.request("POST", "api/v1/ebpf/deny/preview", body: json(d))
    }

    public var hasDryRun: Bool { !removing && action == .deny && kind.hasDryRun }

    public func summarize(_ r: JSONValue) -> String {
        if hasDryRun { return DenyPreview(r).summary }
        let n = r.controlItems.count + (r["items"]?.controlItems.count ?? 0)
        return "No dry run exists for this change. \(n) managed rule(s) currently exist; the server validates the request on confirm."
    }

    public func spec(client c: NetraClient) -> MutationSpec {
        let me = self
        return MutationSpec(title: title, risk: risk, expectedPhrase: expectedPhrase,
                            leaseBound: !removing && action == .deny,
                            preview: { me.previewRequest(c) },
                            summarize: { me.summarize($0) },
                            execute: { _ in me.mutationRequest(c) })
    }

    /// Pre-fills a removal from a row of GET /api/v1/ebpf/rules (models.FirewallRule).
    public static func removal(from row: ControlRow) -> RuleDraft? {
        var d = RuleDraft(); d.removing = true
        let dir = row.text("direction").isEmpty ? "egress" : row.text("direction")
        d.direction = dir
        switch row.text("type") {
        case "ip4", "ip6": d.kind = .ip; d.value = row.text("value")
        case "cidr": d.kind = .cidr; d.value = row.text("cidr")
        case "port": d.kind = .port; d.port = Int(row.text("port")) ?? 0; d.proto = row.text("protocol").isEmpty ? "ANY" : row.text("protocol")
        case "uid": d.kind = .uid; d.value = row.text("value")
        case "dns": d.kind = .dns; d.value = row.text("value")
        case "sni": d.kind = .sni; d.value = row.text("value")
        case "process": d.kind = .process; d.value = row.text("value")
        case "rate": d.kind = .rate; d.value = row.text("destination")
        default: return nil
        }
        return d
    }
}
