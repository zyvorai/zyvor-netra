// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Framing for GET /api/v1/vms/{node}/capture/ws (internal/api/capture.go proxyCaptureStream, one-way
/// agent -> viewer relay of internal/capture.Frame). Starting a capture is a separate mutating PUT
/// /vms/{node}/capture and is NOT done here: this only subscribes to a session someone already started.
/// The route needs the operator role (rbac.go operatorGET) because frames carry packet bytes.
/// Wire frame (little endian): observedAtUnixNano(8) origLen(4) capLen(4) direction(1) family(1) protocol(1)
/// pad(1) data(capLen). Packet bytes are never logged.
public enum VMCapture {
    public static let headerLength = 20
    /// internal/capture MaxCapLen.
    public static let maxCapLen = 9000
    /// In-memory recording cap for the app (64 MiB of pcap).
    public static let maxRecordingBytes = 64 << 20

    public struct Frame: Equatable, Sendable {
        public var observedAtUnixNano: Int64
        public var origLen: UInt32
        public var direction: UInt8, family: UInt8, proto: UInt8
        public var data: Data
    }
    public enum DecodeError: Error, Equatable { case tooShort(Int), lengthMismatch(header: Int, have: Int), tooLarge(Int) }

    public static func capturePath(node: String) -> String {
        "api/v1/vms/\(node.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/"))) ?? node)/capture/ws"
    }
    public static func phrase(node: String) -> String { "capture \(node)" }

    /// Operator role (or above); the server enforces it too.
    public static func availability(whoami: WhoAmI?) -> ConsoleData.Availability {
        guard let w = whoami else { return .disabled("Not connected") }
        guard w.canMutate else { return .disabled("Packet capture streams need the operator role") }
        return .allowed
    }
    public static func decision(whoami: WhoAmI?, typed: String, node: String) -> GateDecision {
        if case .disabled(let r) = availability(whoami: whoami) { return .blocked(reason: r) }
        return MutationGate(canMutate: true).decide(risk: .high, previewed: true, typedPhrase: typed, expectedPhrase: phrase(node: node))
    }

    private static func le<T: FixedWidthInteger>(_ d: Data, _ o: Int, _ t: T.Type) -> T {
        var v: T = 0
        for i in 0..<MemoryLayout<T>.size { v |= T(truncatingIfNeeded: d[d.startIndex + o + i]) << (8 * i) }
        return v
    }

    public static func decode(_ raw: Data) throws -> Frame {
        guard raw.count >= headerLength else { throw DecodeError.tooShort(raw.count) }
        let capLen = Int(le(raw, 12, UInt32.self))
        guard capLen == raw.count - headerLength else { throw DecodeError.lengthMismatch(header: capLen, have: raw.count - headerLength) }
        guard capLen <= maxCapLen else { throw DecodeError.tooLarge(capLen) }
        return Frame(observedAtUnixNano: Int64(bitPattern: le(raw, 0, UInt64.self)), origLen: le(raw, 8, UInt32.self),
                     direction: raw[raw.startIndex + 16], family: raw[raw.startIndex + 17], proto: raw[raw.startIndex + 18],
                     data: raw.subdata(in: (raw.startIndex + headerLength)..<raw.endIndex))
    }
}

/// Classic libpcap (little endian, v2.4, Ethernet), byte-compatible with capture.WritePCAPHeader/Record.
public struct PCAPBuilder: Sendable {
    public private(set) var data = Data()
    public private(set) var frames = 0
    public init() {
        data.reserveCapacity(1 << 16)
        put32(0xa1b2c3d4); put16(2); put16(4); put32(0); put32(0); put32(UInt32(VMCapture.maxCapLen)); put32(1)
    }
    private mutating func put16(_ v: UInt16) { data.append(contentsOf: [UInt8(v & 0xff), UInt8(v >> 8)]) }
    private mutating func put32(_ v: UInt32) { for i in 0..<4 { data.append(UInt8(truncatingIfNeeded: v >> (8 * UInt32(i)))) } }
    /// Returns false (and drops the frame) once the recording cap is reached.
    @discardableResult
    public mutating func append(_ f: VMCapture.Frame) -> Bool {
        guard data.count + 16 + f.data.count <= VMCapture.maxRecordingBytes else { return false }
        let ns = f.observedAtUnixNano
        put32(UInt32(truncatingIfNeeded: ns / 1_000_000_000)); put32(UInt32(truncatingIfNeeded: (ns % 1_000_000_000) / 1000))
        put32(UInt32(f.data.count)); put32(f.origLen)
        data.append(f.data); frames += 1
        return true
    }
}
