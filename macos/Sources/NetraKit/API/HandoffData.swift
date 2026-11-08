// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// The on-call handoff pack (GET /api/v1/handoff). Read-only: it summarises report, playbook, fleet, coverage,
/// audit and drop reasons for a shift note and never applies policy or extends a lease.
public enum HandoffFormat: String, Sendable, CaseIterable, Identifiable {
    case markdown, json
    public var id: String { rawValue }
    public var fileExtension: String { self == .markdown ? "md" : "json" }
}

/// The few headline numbers shown above the pack, read tolerantly from the JSON form.
public struct HandoffHeadline: Sendable, Equatable {
    public var generatedAt: String?
    public var agents: Int?
    public var staleAgents: Int?
    public var workloads: Int?
    public var detachedPrograms: Int?
    public var missingMaps: Int?
    public var quiet: Bool?
    public var dropEvents: Int?
    public var blockedEvents: Int?

    public init() {}

    /// Parses the `format=json` body. Missing sections leave their fields nil rather than failing.
    public static func parse(_ data: Data) -> HandoffHeadline {
        var h = HandoffHeadline()
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return h }
        h.generatedAt = root["generatedAt"] as? String
        if let fleet = root["fleet"] as? [String: Any] {
            h.agents = fleet["agentCount"] as? Int
            h.staleAgents = fleet["staleAgents"] as? Int
            h.workloads = fleet["workloads"] as? Int
        }
        if let cov = root["coverage"] as? [String: Any] {
            h.detachedPrograms = cov["detachedPrograms"] as? Int
            h.missingMaps = cov["missingMapEntries"] as? Int
            h.quiet = cov["quiet"] as? Bool
        }
        if let r = root["reasons"] as? [String: Any] {
            h.dropEvents = r["total"] as? Int
            h.blockedEvents = r["blocked"] as? Int
        }
        return h
    }
}

extension NetraClient {
    /// GET /api/v1/handoff?format=markdown|json. Raw body so it can be copied or saved unchanged.
    public func handoff(_ format: HandoffFormat) async throws -> DownloadedFile {
        try await download("api/v1/handoff", query: [URLQueryItem(name: "format", value: format.rawValue)])
    }
}
