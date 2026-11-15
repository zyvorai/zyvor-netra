// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Connection hints read from a `netractl` config file (`~/.netra/env`) or a bare API-key file (`~/.netra/api-key`).
/// Parsing is pure; `loadHome()` is the I/O path used at launch (real home via getpwuid).
public struct NetractlConfig: Sendable, Equatable {
    public var url: String?
    public var apiKey: String?
    /// True when the file sets NETRA_TLS_INSECURE. The app never skips TLS; it may auto-pin the probed leaf
    /// once, matching the operator's existing CLI opt-in.
    public var requestedInsecureTLS = false

    public init(url: String? = nil, apiKey: String? = nil, requestedInsecureTLS: Bool = false) {
        self.url = url; self.apiKey = apiKey; self.requestedInsecureTLS = requestedInsecureTLS
    }

    public var isEmpty: Bool { url == nil && apiKey == nil }

    /// Reads `~/.netra/env` and `~/.netra/api-key` when present (real home via getpwuid).
    public static func loadHome(fileManager: FileManager = .default) -> NetractlConfig {
        load(directory: realHomeDirectory().appendingPathComponent(".netra"), fileManager: fileManager)
    }

    public static func realHomeDirectory() -> URL {
        #if canImport(Darwin)
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
            return URL(fileURLWithPath: String(cString: dir), isDirectory: true)
        }
        #endif
        return FileManager.default.homeDirectoryForCurrentUser
    }

    /// Testable directory loader: merges `env` then `api-key` under `directory`.
    public static func load(directory: URL, fileManager: FileManager = .default) -> NetractlConfig {
        let names = ["env", "api-key"]
        var parts: [NetractlConfig] = []
        for name in names {
            let url = directory.appendingPathComponent(name)
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            parts.append(parse(text))
        }
        return merge(parts)
    }

    /// Parses `export NETRA_URL=...` / `NETRA_API_KEY=...` lines (quotes and comments tolerated).
    /// A file with no `KEY=` lines is treated as a bare API key (single non-empty line, no whitespace).
    public static func parse(_ text: String) -> NetractlConfig {
        var cfg = NetractlConfig()
        var sawAssignment = false
        for raw in text.split(whereSeparator: \.isNewline) {
            var line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("export ") { line = String(line.dropFirst(7)).trimmingCharacters(in: .whitespaces) }
            guard let eq = line.firstIndex(of: "=") else { continue }
            sawAssignment = true
            let key = line[..<eq].trimmingCharacters(in: .whitespaces)
            let value = unquote(String(line[line.index(after: eq)...]))
            switch key {
            case "NETRA_URL": if let u = validURL(value) { cfg.url = u }
            case "NETRA_API_KEY": if !value.isEmpty { cfg.apiKey = value }
            case "NETRA_TLS_INSECURE": cfg.requestedInsecureTLS = ["1", "true", "yes"].contains(value.lowercased())
            default: break
            }
        }
        if !sawAssignment {
            let bare = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if !bare.isEmpty, !bare.contains(where: \.isWhitespace), bare.count <= 4096 { cfg.apiKey = bare }
        }
        return cfg
    }

    /// Combines several files; later files only fill what earlier ones left empty.
    public static func merge(_ configs: [NetractlConfig]) -> NetractlConfig {
        var out = NetractlConfig()
        for c in configs {
            if out.url == nil { out.url = c.url }
            if out.apiKey == nil { out.apiKey = c.apiKey }
            out.requestedInsecureTLS = out.requestedInsecureTLS || c.requestedInsecureTLS
        }
        return out
    }

    private static func unquote(_ s: String) -> String {
        var v = s.trimmingCharacters(in: .whitespaces)
        if v.count >= 2, let f = v.first, let l = v.last, (f == "\"" && l == "\"") || (f == "'" && l == "'") {
            v = String(v.dropFirst().dropLast())
        }
        return v
    }

    private static func validURL(_ s: String) -> String? {
        guard let u = URL(string: s), let scheme = u.scheme, ["http", "https"].contains(scheme), u.host != nil else { return nil }
        return s
    }
}
