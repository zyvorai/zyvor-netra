// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Builds the body for "Explain this row" (POST /api/v1/ai/explain) from a table row the user selected.
/// The server narrates only what it is sent and never applies anything. The message carries a short list of the
/// row's plain fields; anything that looks like a credential, payload, argv or environment is left out even if the
/// server ever returned it.
public enum RowExplain {
    static let identityKeys = ["subject", "name", "workload", "pod", "node", "host", "id", "ip", "srcIP", "dstIP", "reason", "kind", "type"]
    static let sensitiveFragments = ["token", "secret", "password", "passwd", "authorization", "cookie", "cmdline", "argv", "environ",
                                     "apikey", "api_key", "credential", "payload", "privatekey"]
    static let maxFields = 14
    static let maxValueLength = 80

    public static func isSensitive(_ key: String) -> Bool {
        let k = key.lowercased()
        return k == "env" || sensitiveFragments.contains { k.contains($0) }
    }

    /// Lower-case, hyphenated name for the `page` field ("Drop reasons" -> "drop-reasons").
    public static func pageSlug(_ title: String) -> String {
        title.lowercased().split(whereSeparator: { !$0.isLetter && !$0.isNumber }).joined(separator: "-")
    }

    public static func subject(of row: JSONValue) -> String {
        if let ns = scalar(row["namespace"]), let pod = scalar(row["pod"]) { return "\(ns)/\(pod)" }
        for k in identityKeys { if let v = scalar(row[k]) { return v } }
        return ""
    }

    /// "key=value; key=value" for up to 14 plain fields in key order, each value cut to 80 characters.
    public static func message(of row: JSONValue) -> String {
        guard case .object(let o) = row else { return "" }
        var parts: [String] = []
        for k in o.keys.sorted() where !isSensitive(k) {
            guard let v = scalar(o[k]) else { continue }
            parts.append("\(k)=\(v.count > maxValueLength ? String(v.prefix(maxValueLength)) + "…" : v)")
            if parts.count == maxFields { break }
        }
        return parts.joined(separator: "; ")
    }

    public static func body(page: String, row: JSONValue) -> Data {
        let slug = pageSlug(page)
        return AskData.explainBody(kind: "row", subject: subject(of: row), message: message(of: row),
                                   severity: scalar(row["severity"]) ?? "", page: slug,
                                   question: "Explain this \(page) entry in plain words and say what, if anything, to check next. Do not suggest applying changes.")
    }

    private static func scalar(_ v: JSONValue?) -> String? {
        switch v {
        case .string(let s)?: s.isEmpty ? nil : s
        case .number(let n)?: n == n.rounded() && abs(n) < 1e15 ? String(Int(n)) : String(n)
        case .bool(let b)?: String(b)
        default: nil
        }
    }
}
