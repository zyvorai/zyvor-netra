// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Native RFB (VNC) 3.8 client for the relay at GET /api/v1/vms/{ns}/{name}/vnc (a byte-for-byte relay of
/// KubeVirt's RFB WebSocket). Deliberately small: SecurityType None only, 32bpp true colour, Raw + CopyRect.
/// Clipboard is OFF: ClientCutText is never sent and ServerCutText is discarded. Screen contents and key
/// events are never logged by this layer.

public enum RFBError: Error, Equatable, LocalizedError, Sendable {
    case protocolViolation(String)
    case unsupported(String)
    case refused(String)
    case limit(String)
    case closed(String)
    public var errorDescription: String? {
        switch self {
        case .protocolViolation(let m): "VNC protocol error: \(m)"
        case .unsupported(let m): m
        case .refused(let m): "VNC server refused the connection: \(m)"
        case .limit(let m): "VNC server exceeded a safety limit: \(m)"
        case .closed(let m): m
        }
    }
}

public struct RFBRect: Equatable, Sendable {
    public var x: Int, y: Int, width: Int, height: Int
    public init(x: Int, y: Int, width: Int, height: Int) { self.x = x; self.y = y; self.width = width; self.height = height }
}

public enum RFBLimits {
    public static let maxDimension = 8192
    /// 4096x4096 at 4 bytes per pixel = 64 MiB.
    public static let maxPixels = 16_777_216
    public static let maxNameBytes = 4096
    public static let maxReasonBytes = 4096
    public static let maxCutTextBytes = 1 << 20
    public static let maxRects = 65_535
}

/// BGRX, 4 bytes per pixel, row-major (matches the SetPixelFormat we send: shifts R16 G8 B0, little endian).
public struct RFBFramebuffer: Equatable, Sendable {
    public private(set) var width: Int
    public private(set) var height: Int
    public private(set) var pixels: [UInt8]
    public init(width: Int, height: Int) {
        self.width = width; self.height = height
        pixels = [UInt8](repeating: 0, count: width * height * 4)
    }
    mutating func blit(_ r: RFBRect, raw: Data) {
        let base = raw.startIndex
        for row in 0..<r.height {
            let src = base + row * r.width * 4
            let dst = ((r.y + row) * width + r.x) * 4
            raw.withUnsafeBytes { buf in
                pixels.withUnsafeMutableBytes { out in
                    out.baseAddress!.advanced(by: dst).copyMemory(from: buf.baseAddress!.advanced(by: src - base), byteCount: r.width * 4)
                }
            }
        }
    }
    mutating func copy(from sx: Int, _ sy: Int, to r: RFBRect) {
        var tmp = [UInt8](); tmp.reserveCapacity(r.width * r.height * 4)
        for row in 0..<r.height {
            let s = ((sy + row) * width + sx) * 4
            tmp.append(contentsOf: pixels[s..<(s + r.width * 4)])
        }
        for row in 0..<r.height {
            let d = ((r.y + row) * width + r.x) * 4
            pixels.replaceSubrange(d..<(d + r.width * 4), with: tmp[(row * r.width * 4)..<((row + 1) * r.width * 4)])
        }
    }
}

/// Sans-IO RFB state machine. Feed it bytes from the server; it returns bytes to send back and events.
/// Throws once on a refused/malformed stream and stays failed afterwards.
public struct RFBMachine: Sendable {
    public enum Event: Equatable, Sendable {
        /// Handshake finished (also fired never again: resizing is not negotiated, see class comment).
        case ready(width: Int, height: Int, name: String)
        /// A whole FramebufferUpdate message was applied. `rects` are the changed areas.
        case updated([RFBRect])
        case bell
    }
    public struct Output: Equatable, Sendable { public var replies: [Data] = []; public var events: [Event] = [] }

    enum Phase: Equatable { case version, securityList, securityResult, serverInit, messageType, updateHeader, rects(Int), cutHeader, cutText(Int), failed }
    private var phase: Phase = .version
    private var buf = Data()
    private var changed: [RFBRect] = []
    public private(set) var framebuffer = RFBFramebuffer(width: 0, height: 0)
    public private(set) var serverName = ""
    public var isRunning: Bool { switch phase { case .messageType, .updateHeader, .rects, .cutHeader, .cutText: true; default: false } }

    public init() {}

    public mutating func receive(_ data: Data) throws -> Output {
        if phase == .failed { throw RFBError.protocolViolation("connection already failed") }
        buf.append(data)
        // Bound buffered bytes: one framebuffer update rect or small control message, never unbounded.
        if buf.count > RFBLimits.maxPixels * 4 + 64 * 1024 { phase = .failed; throw RFBError.limit("receive buffer") }
        var out = Output()
        do {
            while try step(&out) {}
        } catch { phase = .failed; buf = Data(); throw error }
        return out
    }

    // MARK: stepping
    private func u16(_ o: Int) -> Int { Int(buf[buf.startIndex + o]) << 8 | Int(buf[buf.startIndex + o + 1]) }
    private func u32(_ o: Int) -> Int { u16(o) << 16 | u16(o + 2) }
    private mutating func take(_ n: Int) { buf.removeFirst(n) }

    private mutating func step(_ out: inout Output) throws -> Bool {
        switch phase {
        case .version:
            guard buf.count >= 12 else { return false }
            let s = String(decoding: buf.prefix(12), as: UTF8.self)
            guard s.hasPrefix("RFB "), s.hasSuffix("\n"), s.count == 12,
                  let major = Int(s.dropFirst(4).prefix(3)), let minor = Int(s.dropFirst(8).prefix(3)) else {
                throw RFBError.protocolViolation("not an RFB server")
            }
            guard major > 3 || (major == 3 && minor >= 8) else {
                throw RFBError.unsupported("VNC server speaks RFB \(major).\(minor); only 3.8 is supported")
            }
            take(12)
            out.replies.append(Data("RFB 003.008\n".utf8))
            phase = .securityList
            return true
        case .securityList:
            guard buf.count >= 1 else { return false }
            let n = Int(buf[buf.startIndex])
            if n == 0 {
                guard buf.count >= 5 else { return false }
                let len = u32(1)
                guard len <= RFBLimits.maxReasonBytes else { throw RFBError.limit("failure reason") }
                guard buf.count >= 5 + len else { return false }
                throw RFBError.refused(String(decoding: buf.dropFirst(5).prefix(len), as: UTF8.self))
            }
            guard buf.count >= 1 + n else { return false }
            let types = Array(buf.dropFirst().prefix(n))
            guard types.contains(1) else {
                let names = types.map { RFBMachine.securityName($0) }.joined(separator: ", ")
                throw RFBError.unsupported("This VM's VNC requires authentication (\(names)). Only 'None' is supported; use the browser console instead.")
            }
            take(1 + n)
            out.replies.append(Data([1]))
            phase = .securityResult
            return true
        case .securityResult:
            guard buf.count >= 4 else { return false }
            let r = u32(0)
            if r != 0 {
                // 3.8: failure carries a reason string.
                guard buf.count >= 8 else { return false }
                let len = u32(4)
                guard len <= RFBLimits.maxReasonBytes else { throw RFBError.limit("failure reason") }
                guard buf.count >= 8 + len else { return false }
                throw RFBError.refused(String(decoding: buf.dropFirst(8).prefix(len), as: UTF8.self))
            }
            take(4)
            out.replies.append(Data([1])) // ClientInit: shared
            phase = .serverInit
            return true
        case .serverInit:
            guard buf.count >= 24 else { return false }
            let w = u16(0), h = u16(2), nameLen = u32(20)
            guard w >= 1, h >= 1, w <= RFBLimits.maxDimension, h <= RFBLimits.maxDimension, w * h <= RFBLimits.maxPixels else {
                throw RFBError.limit("framebuffer \(w)x\(h)")
            }
            guard nameLen <= RFBLimits.maxNameBytes else { throw RFBError.limit("desktop name") }
            guard buf.count >= 24 + nameLen else { return false }
            let name = String(decoding: buf.dropFirst(24).prefix(nameLen), as: UTF8.self)
            take(24 + nameLen)
            framebuffer = RFBFramebuffer(width: w, height: h)
            serverName = name
            out.replies.append(RFBMachine.setPixelFormat)
            out.replies.append(RFBMachine.setEncodings)
            out.replies.append(updateRequest(incremental: false))
            out.events.append(.ready(width: w, height: h, name: name))
            phase = .messageType
            return true
        case .messageType:
            guard buf.count >= 1 else { return false }
            switch buf[buf.startIndex] {
            case 0: take(1); phase = .updateHeader
            case 2: take(1); out.events.append(.bell)
            case 3: take(1); phase = .cutHeader
            case let t: throw RFBError.unsupported("unsupported server message type \(t)")
            }
            return true
        case .updateHeader:
            guard buf.count >= 3 else { return false }
            let n = u16(1)
            take(3)
            changed = []
            if n == 0 { finishUpdate(&out) } else { phase = .rects(n) }
            return true
        case .rects(let left):
            guard buf.count >= 12 else { return false }
            let r = RFBRect(x: u16(0), y: u16(2), width: u16(4), height: u16(6))
            let enc = Int32(truncatingIfNeeded: u32(8))
            guard r.x + r.width <= framebuffer.width, r.y + r.height <= framebuffer.height else {
                throw RFBError.limit("rectangle outside framebuffer")
            }
            let payload: Int
            switch enc {
            case 0: payload = r.width * r.height * 4
            case 1: payload = 4
            default: throw RFBError.unsupported("server sent unsupported encoding \(enc); only Raw and CopyRect are implemented")
            }
            guard buf.count >= 12 + payload else { return false }
            if r.width > 0, r.height > 0 {
                if enc == 0 {
                    framebuffer.blit(r, raw: buf.subdata(in: (buf.startIndex + 12)..<(buf.startIndex + 12 + payload)))
                } else {
                    let sx = u16(12), sy = u16(14)
                    guard sx + r.width <= framebuffer.width, sy + r.height <= framebuffer.height else {
                        throw RFBError.limit("CopyRect source outside framebuffer")
                    }
                    framebuffer.copy(from: sx, sy, to: r)
                }
                changed.append(r)
            }
            take(12 + payload)
            if left <= 1 { finishUpdate(&out) } else { phase = .rects(left - 1) }
            return true
        case .cutHeader:
            guard buf.count >= 7 else { return false }
            let len = u32(3)
            guard len <= RFBLimits.maxCutTextBytes else { throw RFBError.limit("clipboard text") }
            take(7)
            phase = len == 0 ? .messageType : .cutText(len)
            return true
        case .cutText(let len):
            let n = min(len, buf.count)
            guard n > 0 else { return false }
            take(n)
            phase = n == len ? .messageType : .cutText(len - n)
            return true
        case .failed: return false
        }
    }

    private mutating func finishUpdate(_ out: inout Output) {
        out.events.append(.updated(changed))
        out.replies.append(updateRequest(incremental: true))
        changed = []
        phase = .messageType
    }

    // MARK: client messages
    private func be16(_ v: Int) -> [UInt8] { [UInt8(truncatingIfNeeded: v >> 8), UInt8(truncatingIfNeeded: v)] }
    func updateRequest(incremental: Bool) -> Data {
        Data([3, incremental ? 1 : 0] + be16(0) + be16(0) + be16(framebuffer.width) + be16(framebuffer.height))
    }
    /// 32 bpp, depth 24, little endian, true colour, 255/255/255, shifts 16/8/0.
    static let setPixelFormat = Data([0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0])
    /// Raw (0), CopyRect (1).
    static let setEncodings = Data([2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1])

    static func securityName(_ t: UInt8) -> String {
        switch t { case 2: "VNC password"; case 16: "Tight"; case 18: "TLS"; case 19: "VeNCrypt"; case 5: "RA2"; default: "type \(t)" }
    }

    /// Pointer event. Coordinates are clamped to the framebuffer. Empty until the handshake finished.
    public func pointerEvent(x: Int, y: Int, buttons: UInt8) -> Data? {
        guard isRunning else { return nil }
        let cx = max(0, min(x, framebuffer.width - 1)), cy = max(0, min(y, framebuffer.height - 1))
        return Data([5, buttons] + be16(cx) + be16(cy))
    }
    public func keyEvent(keysym: UInt32, down: Bool) -> Data? {
        guard isRunning else { return nil }
        return Data([4, down ? 1 : 0, 0, 0] + [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: keysym >> $0) })
    }
}

// MARK: - Driver

public protocol RFBTransport: Sendable {
    func send(_ data: Data) async throws
    /// Next chunk from the server; nil when the peer closed cleanly.
    func receive() async throws -> Data?
    func close()
}

/// Drives an RFBMachine over a transport. Not tied to UI: `run` reports every applied update.
public actor RFBClient {
    private var machine = RFBMachine()
    private let transport: RFBTransport
    public init(transport: RFBTransport) { self.transport = transport }

    public var framebuffer: RFBFramebuffer { machine.framebuffer }
    public var serverName: String { machine.serverName }

    /// Runs until the server closes (returns) or an error is thrown. `onEvent` sees ready/updated/bell.
    public func run(onEvent: @Sendable (RFBMachine.Event, RFBFramebuffer) -> Void) async throws {
        defer { transport.close() }
        while let chunk = try await transport.receive() {
            let out = try machine.receive(chunk)
            for r in out.replies { try await transport.send(r) }
            for e in out.events { onEvent(e, machine.framebuffer) }
        }
    }

    public func pointer(x: Int, y: Int, buttons: UInt8) async {
        if let d = machine.pointerEvent(x: x, y: y, buttons: buttons) { try? await transport.send(d) }
    }
    public func key(keysym: UInt32, down: Bool) async {
        if let d = machine.keyEvent(keysym: keysym, down: down) { try? await transport.send(d) }
    }
    public func close() { transport.close() }
}

/// Adapts ConsoleSocket (binary frames) to RFBTransport. Text frames are ignored.
public final class RFBSocketTransport: RFBTransport, @unchecked Sendable {
    private let socket: ConsoleSocket
    private var it: AsyncStream<ConsoleSocket.Event>.Iterator
    public init(socket: ConsoleSocket) { self.socket = socket; it = socket.events.makeAsyncIterator() }
    public func send(_ data: Data) async throws { try await socket.send(data: data) }
    public func receive() async throws -> Data? {
        while let ev = await it.next() {
            switch ev {
            case .binary(let d): return d
            case .failed(let m): throw RFBError.closed(m)
            case .closed(_, let reason): if reason.isEmpty { return nil } else { throw RFBError.closed(reason) }
            case .opened, .text: continue
            }
        }
        return nil
    }
    public func close() { socket.close() }
}
