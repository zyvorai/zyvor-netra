// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

// MARK: exports

public enum OpsExportKind: String, CaseIterable, Sendable, Identifiable {
    case flows, events, blocks, audit
    public var id: String { rawValue }
    public var title: String { rawValue.capitalized }
    public var path: String { "api/v1/export/\(rawValue)" }
    /// Server default and ceiling for `limit` (export.go / ops.go).
    public var defaultLimit: Int { switch self { case .flows, .blocks: 200; default: 100 } }
    public var maxLimit: Int { switch self { case .flows, .blocks: 2000; default: 500 } }
}

/// Formats accepted by siem.NormalizeFormat (aliases normalise server-side).
public enum OpsExportFormat: String, CaseIterable, Sendable, Identifiable {
    case json, jsonl, cef, syslog, otlp, otlpTrace = "otlp-trace"
    public var id: String { rawValue }
    public var fileExtension: String { switch self { case .jsonl: "jsonl"; case .cef, .syslog: "log"; default: "json" } }
}

public enum OpsData {
    public static func exportQuery(format: OpsExportFormat, limit: Int, kind: OpsExportKind) -> [URLQueryItem] {
        let l = min(max(limit, 1), kind.maxLimit)
        return [.init(name: "format", value: format.rawValue), .init(name: "limit", value: "\(l)")]
    }

    public static func exportFilename(kind: OpsExportKind, format: OpsExportFormat, date: Date = Date()) -> String {
        let f = DateFormatter(); f.dateFormat = "yyyyMMdd-HHmmss"; f.timeZone = TimeZone(identifier: "UTC")
        return "netra-\(kind.rawValue)-\(f.string(from: date)).\(format.fileExtension)"
    }

    public static func exportPath(kind: OpsExportKind) -> String { kind.path }

    /// Artifact ids are listed by the capture history (there is no list route for /capture/artifacts).
    public static func artifactRows(fromHistory v: JSONValue) -> [ControlRow] {
        controlRows(v, listKey: "entries", idKeys: ["artifactId"]).filter { !($0.value["artifactId"]?.string ?? "").isEmpty }
    }

    /// Active + recent sessions from GET /capture/summaries, tagged so one table can show both.
    public static func summaryRows(_ v: JSONValue) -> [ControlRow] {
        var out: [ControlRow] = []
        for (key, tag) in [("active", "active"), ("history", "ended")] {
            for (i, item) in (v[key]?.controlItems ?? []).enumerated() {
                var o: [String: JSONValue] = [:]
                if case .object(let d) = item { o = d }
                o["state"] = .string(tag)
                let sum = item["summary"]
                o["frames"] = sum?["frames"] ?? .null
                o["bytes"] = sum?["bytes"] ?? .null
                out.append(ControlRow(id: "\(tag)-\(item["node"]?.string ?? "")-\(i)", value: .object(o)))
            }
        }
        return out
    }

    public static let wiresharkPath = "/Applications/Wireshark.app"
    public static func wiresharkInstalled(_ fm: FileManager = .default) -> Bool { fm.fileExists(atPath: wiresharkPath) }

    /// Artifact ids are opaque server strings used in a URL path; refuse anything that could escape it.
    public static func isSafeArtifactID(_ id: String) -> Bool {
        !id.isEmpty && !id.contains("/") && !id.contains("..") && !id.contains("\\")
    }
}

// MARK: gitops

public struct GitOpsManifest: Sendable, Equatable, Identifiable {
    public var path, namespace, name: String
    public var drifted, applied: Bool
    public var risk, error, note: String?
    public var manifestJSON: Data?
    public var id: String { path.isEmpty ? "\(namespace)/\(name)" : path }
}

public struct GitOpsStatus: Sendable, Equatable {
    public var lastRun: String, dir: String
    public var autoApply: Bool
    public var manifests: [GitOpsManifest]
    public var loadErrors: [String]
    public init(_ v: JSONValue) {
        lastRun = v["lastRun"]?.string ?? ""; dir = v["dir"]?.string ?? ""
        if case .bool(let b)? = v["autoApply"] { autoApply = b } else { autoApply = false }
        loadErrors = (v["loadErrors"]?.controlItems ?? []).compactMap(\.string)
        manifests = (v["manifests"]?.controlItems ?? []).map { m in
            func flag(_ k: String) -> Bool { if case .bool(let b)? = m[k] { b } else { false } }
            let enc = JSONEncoder(); enc.outputFormatting = [.sortedKeys]
            return GitOpsManifest(path: m["path"]?.string ?? "", namespace: m["namespace"]?.string ?? "", name: m["name"]?.string ?? "",
                                  drifted: flag("drifted"), applied: flag("applied"), risk: m["plan"]?["risk"]?.string,
                                  error: m["error"]?.string, note: m["note"]?.string,
                                  manifestJSON: m["manifest"].flatMap { try? enc.encode($0) })
        }
    }
}
