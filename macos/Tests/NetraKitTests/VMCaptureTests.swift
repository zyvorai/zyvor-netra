// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class VMCaptureTests: XCTestCase {
    func wire(ns: Int64, orig: UInt32, cap: UInt32? = nil, data: [UInt8]) -> Data {
        var d = Data()
        func le(_ v: UInt64, _ n: Int) { for i in 0..<n { d.append(UInt8(truncatingIfNeeded: v >> (8 * UInt64(i)))) } }
        le(UInt64(bitPattern: ns), 8); le(UInt64(orig), 4); le(UInt64(cap ?? UInt32(data.count)), 4)
        d.append(contentsOf: [1, 2, 6, 0]); d.append(contentsOf: data)
        return d
    }

    func testDecode() throws {
        let f = try VMCapture.decode(wire(ns: 1_700_000_000_123_456_789, orig: 100, data: [0xde, 0xad]))
        XCTAssertEqual(f.observedAtUnixNano, 1_700_000_000_123_456_789)
        XCTAssertEqual(f.origLen, 100); XCTAssertEqual(f.direction, 1); XCTAssertEqual(f.family, 2); XCTAssertEqual(f.proto, 6)
        XCTAssertEqual(f.data, Data([0xde, 0xad]))
    }
    func testDecodeRejectsBadFrames() {
        XCTAssertThrowsError(try VMCapture.decode(Data(count: 19)))
        XCTAssertThrowsError(try VMCapture.decode(wire(ns: 0, orig: 1, cap: 5, data: [1])))
        XCTAssertThrowsError(try VMCapture.decode(wire(ns: 0, orig: 1, data: [UInt8](repeating: 0, count: 9001))))
    }
    func testDecodeSliceIndices() throws {
        let big = Data([9, 9]) + wire(ns: 5, orig: 1, data: [7])
        XCTAssertEqual(try VMCapture.decode(big.dropFirst(2)).data, Data([7]))
    }
    func testPCAPLayout() throws {
        var b = PCAPBuilder()
        XCTAssertEqual(b.data.count, 24)
        XCTAssertEqual(Array(b.data.prefix(8)), [0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0])
        XCTAssertEqual(b.data[20], 1)   // Ethernet
        XCTAssertTrue(b.append(try VMCapture.decode(wire(ns: 3_000_002_000, orig: 60, data: [1, 2, 3]))))
        let rec = Array(b.data.dropFirst(24))
        XCTAssertEqual(rec, [3, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 60, 0, 0, 0, 1, 2, 3])
        XCTAssertEqual(b.frames, 1)
    }
    func testGateAndPath() {
        XCTAssertEqual(VMCapture.capturePath(node: "n/1"), "api/v1/vms/n%2F1/capture/ws")
        XCTAssertEqual(VMCapture.phrase(node: "n1"), "capture n1")
        XCTAssertEqual(VMCapture.decision(whoami: nil, typed: "", node: "n1"), .blocked(reason: "Not connected"))
        let viewer = WhoAmI(authRequired: true, oidcEnabled: false, kind: "token", role: "viewer", identity: nil)
        let op = WhoAmI(authRequired: true, oidcEnabled: false, kind: "token", role: "operator", identity: nil)
        XCTAssertEqual(VMCapture.availability(whoami: viewer), .disabled("Packet capture streams need the operator role"))
        XCTAssertEqual(VMCapture.decision(whoami: op, typed: "capture n1", node: "n1"), .allowed(confirmRiskHeader: true))
        XCTAssertEqual(VMCapture.decision(whoami: op, typed: "x", node: "n1"), .needsTypedConfirmation(phrase: "capture n1"))
    }
}
