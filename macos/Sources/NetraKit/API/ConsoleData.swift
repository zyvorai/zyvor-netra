// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Pure helpers for the workload console routes (internal/api/console.go).
/// Exec: GET /api/v1/pods/{ns}/{name}/exec?container=&command= upgraded to a WebSocket (admin role, needs
/// NETRA_WORKLOAD_CONSOLE=true). Client text/binary frames are stdin, except a JSON text frame
/// {"type":"resize","cols":N,"rows":N}. Server frames are raw stdout/stderr bytes (binary); a text frame is a
/// server-side notice ("exec error: ..." or "\r\n[exec] ..."). No subprotocol is negotiated.
/// VNC: GET /api/v1/vms/{ns}/{name}/vnc is a byte-for-byte relay of KubeVirt's RFB WebSocket.
public enum ConsoleData {
    /// Discovery flag: `consoleEnabled` in GET /api/v1/status.
    public static let statusPath = "api/v1/status"

    public static func consoleEnabled(fromStatus data: Data) -> Bool {
        ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])?["consoleEnabled"] as? Bool ?? false
    }

    private static func seg(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/"))) ?? s
    }
    public static func execPath(namespace: String, name: String) -> String { "api/v1/pods/\(seg(namespace))/\(seg(name))/exec" }
    public static func vncPath(namespace: String, name: String) -> String { "api/v1/vms/\(seg(namespace))/\(seg(name))/vnc" }

    public static func execQuery(container: String?, command: String = "/bin/sh") -> [URLQueryItem] {
        var q = [URLQueryItem(name: "command", value: command.isEmpty ? "/bin/sh" : command)]
        if let c = container, !c.isEmpty { q.append(URLQueryItem(name: "container", value: c)) }
        return q
    }

    /// http(s) -> ws(s). Anything else is returned unchanged.
    public static func webSocketURL(_ url: URL) -> URL {
        guard var c = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return url }
        switch c.scheme?.lowercased() {
        case "https": c.scheme = "wss"
        case "http": c.scheme = "ws"
        default: break
        }
        return c.url ?? url
    }

    /// Where the web UI hosts the VNC console (Workloads page), for the browser handoff.
    public static func webUIURL(base: URL) -> URL { base.appendingPathComponent("") }

    /// Resize frame understood by proxyPodExec.
    public static func resizeMessage(cols: Int, rows: Int) -> String {
        "{\"type\":\"resize\",\"cols\":\(max(1, min(cols, 1000))),\"rows\":\(max(1, min(rows, 1000)))}"
    }

    /// Phrase the operator must type before an exec session opens.
    public static func execPhrase(namespace: String, name: String) -> String { "exec \(namespace)/\(name)" }

    public enum Availability: Equatable, Sendable {
        case allowed
        case disabled(String)
    }
    /// Console controls need: server flag on, token not read-only, and admin role (server RBAC adminOnly).
    public static func availability(consoleEnabled: Bool?, whoami: WhoAmI?) -> Availability {
        guard let w = whoami else { return .disabled("Not connected") }
        guard let on = consoleEnabled else { return .disabled("Checking console availability…") }
        guard on else { return .disabled("Console is disabled on the server (set NETRA_WORKLOAD_CONSOLE=true)") }
        guard MutationGate(canMutate: w.canMutate).canMutate else { return .disabled("This token is read-only") }
        guard w.isAdmin else { return .disabled("Consoles need the admin role") }
        return .allowed
    }

    /// Exec is high risk: typed phrase required (the server has no confirm header for consoles).
    public static func execDecision(whoami: WhoAmI?, consoleEnabled: Bool?, typed: String, namespace: String, name: String) -> GateDecision {
        if case .disabled(let r) = availability(consoleEnabled: consoleEnabled, whoami: whoami) { return .blocked(reason: r) }
        return MutationGate(canMutate: true).decide(risk: .high, previewed: true, typedPhrase: typed,
                                                    expectedPhrase: execPhrase(namespace: namespace, name: name))
    }

    public enum Notice: Equatable, Sendable { case none, execError(String), execStatus(String) }
    /// Classifies a server text frame (frames are notices, never stdout).
    public static func classify(textFrame s: String) -> Notice {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.hasPrefix("exec error:") { return .execError(String(t.dropFirst("exec error:".count)).trimmingCharacters(in: .whitespaces)) }
        if t.hasPrefix("[exec]") { return .execStatus(String(t.dropFirst("[exec]".count)).trimmingCharacters(in: .whitespaces)) }
        return .none
    }
}

/// Decodes UTF-8 across chunk boundaries (a multi-byte scalar may be split between frames).
public struct ConsoleUTF8Decoder: Sendable {
    private var pending = Data()
    public init() {}
    public mutating func feed(_ chunk: Data) -> String {
        pending.append(chunk)
        var cut = pending.count
        // Hold back an incomplete trailing sequence (at most 3 bytes).
        var i = pending.count - 1, back = 0
        while i >= 0, back < 4 {
            let b = pending[pending.startIndex + i]
            if b & 0xC0 == 0x80 { i -= 1; back += 1; continue }
            let need = b >= 0xF0 ? 4 : b >= 0xE0 ? 3 : b >= 0xC0 ? 2 : 1
            if need > back + 1 { cut = i }
            break
        }
        let head = pending.prefix(cut)
        pending = Data(pending.suffix(pending.count - cut))
        return String(decoding: head, as: UTF8.self)
    }
}

/// Minimal terminal model: strips ANSI escapes (CSI, OSC, two-byte ESC), honours \n, \r and backspace,
/// drops other control characters. Escape sequences split across chunks are handled.
public struct ConsoleScreen: Sendable, Equatable {
    private enum State: Sendable { case text, esc, csi, osc, oscEsc }
    private var state: State = .text
    public private(set) var lines: [String] = []
    private var current: [Character] = []
    private var col = 0
    public var maxLines: Int
    public init(maxLines: Int = 5000) { self.maxLines = maxLines }

    /// Completed lines plus the one being written.
    public var text: String { (lines + [String(current)]).joined(separator: "\n") }

    public mutating func feed(_ s: String) {
        for ch in s.unicodeScalars {
            switch state {
            case .text:
                switch ch.value {
                case 0x1B: state = .esc
                case 0x0A: newline()
                case 0x0D: col = 0
                case 0x08, 0x7F: if col > 0 { col -= 1 }
                case 0x09: put(" ", repeat: 8 - col % 8)
                case 0..<0x20: break
                default: put(Character(ch), repeat: 1)
                }
            case .esc:
                switch ch {
                case "[": state = .csi
                case "]": state = .osc
                default: state = .text   // two-byte escape (e.g. ESC =, ESC c)
                }
            case .csi:
                // Final byte 0x40...0x7E ends the sequence. "K" (erase to end of line) is honoured.
                if (0x40...0x7E).contains(ch.value) {
                    if ch == "K", col < current.count { current.removeSubrange(col...) }
                    state = .text
                }
            case .osc:
                if ch.value == 0x07 { state = .text } else if ch.value == 0x1B { state = .oscEsc }
            case .oscEsc: state = .text
            }
        }
    }

    private mutating func put(_ c: Character, repeat n: Int) {
        for _ in 0..<max(1, n) {
            if col < current.count { current[col] = c } else { current.append(c) }
            col += 1
        }
    }
    private mutating func newline() {
        lines.append(String(current)); current = []; col = 0
        if lines.count > maxLines { lines.removeFirst(lines.count - maxLines) }
    }
}
