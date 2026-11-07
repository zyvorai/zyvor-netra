// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

public struct SSEEvent: Sendable, Equatable {
    public var event: String
    public var data: String
    public var id: String?
}

/// Incremental Server-Sent Events parser (flows/stream, metrics/stream, capture/stream).
public struct SSEParser: Sendable {
    private var buffer = ""
    private var event = "message", data: [String] = [], id: String?
    public init() {}

    public mutating func feed(_ chunk: String) -> [SSEEvent] {
        buffer += chunk.replacingOccurrences(of: "\r\n", with: "\n")
        var out: [SSEEvent] = []
        while let nl = buffer.firstIndex(of: "\n") {
            let line = String(buffer[..<nl])
            buffer.removeSubrange(...nl)
            if line.isEmpty {
                if !data.isEmpty { out.append(SSEEvent(event: event, data: data.joined(separator: "\n"), id: id)) }
                event = "message"; data = []; continue
            }
            if line.hasPrefix(":") { continue }
            let parts = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            let field = String(parts[0])
            var value = parts.count > 1 ? String(parts[1]) : ""
            if value.hasPrefix(" ") { value.removeFirst() }
            switch field {
            case "event": event = value
            case "data": data.append(value)
            case "id": id = value
            default: break
            }
        }
        return out
    }
}
