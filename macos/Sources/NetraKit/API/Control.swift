// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// One row of a control table, read schema-lessly so older/newer servers still render.
public struct ControlRow: Identifiable, Sendable, Equatable {
    public let id: String
    public let value: JSONValue
    public init(id: String, value: JSONValue) { self.id = id; self.value = value }
    /// Dotted-path text lookup ("summary.hits"); arrays/objects render as counts.
    public func text(_ key: String) -> String {
        var v: JSONValue? = value
        for part in key.split(separator: ".") { v = v?[String(part)] }
        guard let v, v != .null else { return "" }
        return v.summary
    }
}

extension JSONValue {
    public var controlItems: [JSONValue] { if case .array(let a) = self { a } else { [] } }
    public var controlInt: Int? { double.map { Int($0) } }
}

public func controlRows(_ v: JSONValue, listKey: String, idKeys: [String] = ["id"]) -> [ControlRow] {
    let list: [JSONValue] = v.controlItems.isEmpty ? (v[listKey]?.controlItems ?? []) : v.controlItems
    return list.enumerated().map { i, item in
        let id = idKeys.compactMap { k in item[k].flatMap { $0 == .null ? nil : $0.summary } }.joined(separator: "/")
        return ControlRow(id: id.isEmpty ? "row-\(i)" : id + "#\(i)", value: item)
    }
}

/// Result of POST /api/v1/ebpf/deny/preview (internal/denysim.Result), tolerant of missing fields.
public struct DenyPreview: Sendable, Equatable {
    public var hitCount: Int
    public var totalPackets: Int
    public var agentsSeen: Int
    public var agentsStale: Int
    public var caveat: String
    public init(_ v: JSONValue) {
        hitCount = v["hitCount"]?.controlInt ?? 0; totalPackets = v["totalPackets"]?.controlInt ?? 0
        agentsSeen = v["agentsSeen"]?.controlInt ?? 0; agentsStale = v["agentsStale"]?.controlInt ?? 0
        caveat = v["caveat"]?.string ?? ""
    }
    public var summary: String {
        "Would have matched \(hitCount) observed flow(s), \(totalPackets) packet(s) across \(agentsSeen) agent(s)"
            + (agentsStale > 0 ? " (\(agentsStale) stale)" : "") + (caveat.isEmpty ? "" : ". " + caveat)
    }
}

public enum DenyDirection: String, CaseIterable, Sendable { case egress, ingress, both }

extension NetraClient {
    private func jsonGet(_ path: String, _ q: [URLQueryItem] = []) async throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: await send(request("GET", path, query: q)))
    }
    public func rules() async throws -> [ControlRow] {
        controlRows(try await jsonGet("api/v1/ebpf/rules"), listKey: "items")
    }
    public func ruleHistory(id: String, limit: Int = 50) async throws -> [ControlRow] {
        controlRows(try await jsonGet("api/v1/ebpf/rules/\(id)/history", [.init(name: "limit", value: "\(limit)")]), listKey: "items")
    }
    public func policies(namespace: String = "default") async throws -> [ControlRow] {
        // Raw Kubernetes list: {"items":[{metadata:{name,namespace},spec}]}
        let v = try await jsonGet("api/v1/policies", [.init(name: "namespace", value: namespace)])
        return controlRows(v, listKey: "items", idKeys: [])
    }
    public func policyHistory(namespace: String = "", name: String = "", limit: Int = 50) async throws -> [ControlRow] {
        var q = [URLQueryItem(name: "limit", value: "\(limit)")]
        if !namespace.isEmpty { q.append(.init(name: "namespace", value: namespace)) }
        if !name.isEmpty { q.append(.init(name: "name", value: name)) }
        return controlRows(try await jsonGet("api/v1/policies/history", q), listKey: "items")
    }
    public func features() async throws -> [ControlRow] {
        controlRows(try await jsonGet("api/v1/features"), listKey: "features")
    }
    public func captureActive() async throws -> [ControlRow] {
        controlRows(try await jsonGet("api/v1/capture/status"), listKey: "active", idKeys: ["node"])
    }
    public func captureHistory(limit: Int = 50) async throws -> [ControlRow] {
        controlRows(try await jsonGet("api/v1/capture/history", [.init(name: "limit", value: "\(limit)")]), listKey: "entries", idKeys: ["node", "startedAt"])
    }

    // MARK: mutation requests (sent only through MutationFlow)
    public func denyPreviewRequest(ip: String, direction: DenyDirection) -> URLRequest {
        let body = try? JSONSerialization.data(withJSONObject: ["kind": "ip", "value": ip, "direction": direction.rawValue])
        return request("POST", "api/v1/ebpf/deny/preview", body: body)
    }
    public func denyRequest(ip: String, direction: DenyDirection, confirmRisk: Bool) -> URLRequest {
        let body = try? JSONSerialization.data(withJSONObject: ["ip": ip, "direction": direction.rawValue])
        return request("POST", "api/v1/ebpf/deny", body: body, confirmRisk: confirmRisk)
    }
    public func ruleRollbackRequest(id: String, revision: String, confirmRisk: Bool) -> URLRequest {
        request("POST", "api/v1/ebpf/rules/\(id)/rollback/\(revision)", confirmRisk: confirmRisk)
    }
}
