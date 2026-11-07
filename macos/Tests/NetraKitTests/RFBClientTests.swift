// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class FakeRFBTransport: RFBTransport, @unchecked Sendable {
    private let lock = NSLock()
    var chunks: [Data]
    var sent: [Data] = []
    init(_ chunks: [Data]) { self.chunks = chunks }
    func send(_ data: Data) async throws { lock.withLock { sent.append(data) } }
    func receive() async throws -> Data? { lock.withLock { chunks.isEmpty ? nil : chunks.removeFirst() } }
    func close() {}
}

final class RFBClientTests: XCTestCase {
    func be16(_ v: Int) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xff)] }
    func be32(_ v: Int) -> [UInt8] { be16(v >> 16) + be16(v & 0xffff) }

    func serverInit(w: Int, h: Int, name: String = "vm") -> Data {
        Data(be16(w) + be16(h) + [32, 24, 0, 1] + be16(255) + be16(255) + be16(255) + [16, 8, 0, 0, 0, 0] + be32(name.utf8.count) + Array(name.utf8))
    }
    func handshake(w: Int = 4, h: Int = 2) -> Data {
        Data("RFB 003.008\n".utf8) + Data([1, 1]) + Data(be32(0)) + serverInit(w: w, h: h)
    }
    func rect(x: Int, y: Int, w: Int, h: Int, enc: Int) -> [UInt8] { be16(x) + be16(y) + be16(w) + be16(h) + be32(enc) }

    func testHandshakeRepliesAndReady() throws {
        var m = RFBMachine()
        let out = try m.receive(handshake())
        XCTAssertEqual(out.replies[0], Data("RFB 003.008\n".utf8))
        XCTAssertEqual(out.replies[1], Data([1]))            // chose None
        XCTAssertEqual(out.replies[2], Data([1]))            // ClientInit shared
        XCTAssertEqual(out.replies[3][0], 0)                 // SetPixelFormat
        XCTAssertEqual(out.replies[3].count, 20)
        XCTAssertEqual(out.replies[3][4], 32)
        XCTAssertEqual(out.replies[4], Data([2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1]))
        XCTAssertEqual(out.replies[5], Data([3, 0, 0, 0, 0, 0, 0, 4, 0, 2])) // full, non-incremental
        XCTAssertEqual(out.events, [.ready(width: 4, height: 2, name: "vm")])
        XCTAssertTrue(m.isRunning)
    }

    func testHandshakeSplitAcrossChunks() throws {
        var m = RFBMachine()
        let all = handshake()
        var events = [RFBMachine.Event]()
        for b in all { events += try m.receive(Data([b])).events }
        XCTAssertEqual(events, [.ready(width: 4, height: 2, name: "vm")])
    }

    func testRawRectangleAndIncrementalRequest() throws {
        var m = RFBMachine(); _ = try m.receive(handshake())
        let px: [UInt8] = [1, 2, 3, 0, 4, 5, 6, 0]   // two BGRX pixels
        let msg = Data([0, 0] + be16(1) + rect(x: 1, y: 1, w: 2, h: 1, enc: 0) + px)
        let out = try m.receive(msg)
        XCTAssertEqual(out.events, [.updated([RFBRect(x: 1, y: 1, width: 2, height: 1)])])
        XCTAssertEqual(out.replies, [Data([3, 1, 0, 0, 0, 0, 0, 4, 0, 2])])
        let fb = m.framebuffer.pixels
        XCTAssertEqual(Array(fb[((1 * 4 + 1) * 4)..<((1 * 4 + 3) * 4)]), px)
        XCTAssertEqual(fb[0], 0)
    }

    func testCopyRectIncludingOverlap() throws {
        var m = RFBMachine(); _ = try m.receive(handshake(w: 4, h: 1))
        let px: [UInt8] = [1, 1, 1, 0, 2, 2, 2, 0, 3, 3, 3, 0, 4, 4, 4, 0]
        _ = try m.receive(Data([0, 0] + be16(1) + rect(x: 0, y: 0, w: 4, h: 1, enc: 0) + px))
        // copy pixels 0..2 to 1..3 (overlapping)
        let out = try m.receive(Data([0, 0] + be16(1) + rect(x: 1, y: 0, w: 3, h: 1, enc: 1) + be16(0) + be16(0)))
        XCTAssertEqual(out.events.count, 1)
        XCTAssertEqual(Array(m.framebuffer.pixels), [1, 1, 1, 0, 1, 1, 1, 0, 2, 2, 2, 0, 3, 3, 3, 0])
    }

    func testRectSplitMidPayloadWaits() throws {
        var m = RFBMachine(); _ = try m.receive(handshake())
        let full = Data([0, 0] + be16(1) + rect(x: 0, y: 0, w: 1, h: 1, enc: 0) + [9, 8, 7, 0])
        XCTAssertTrue(try m.receive(full.prefix(full.count - 2)).events.isEmpty)
        XCTAssertEqual(try m.receive(full.suffix(2)).events.count, 1)
        XCTAssertEqual(Array(m.framebuffer.pixels.prefix(4)), [9, 8, 7, 0])
    }

    func testBellAndServerCutTextIgnored() throws {
        var m = RFBMachine(); _ = try m.receive(handshake())
        let out = try m.receive(Data([2, 3, 0, 0, 0] + be32(3) + Array("abc".utf8)))
        XCTAssertEqual(out.events, [.bell])
        XCTAssertTrue(out.replies.isEmpty)           // clipboard stays off: nothing sent back
        XCTAssertTrue(m.isRunning)
    }

    func testRefusesAuthentication() {
        var m = RFBMachine()
        XCTAssertThrowsError(try m.receive(Data("RFB 003.008\n".utf8) + Data([1, 2]))) {
            guard case RFBError.unsupported(let msg) = $0 else { return XCTFail("\($0)") }
            XCTAssertTrue(msg.contains("VNC password")); XCTAssertTrue(msg.contains("browser"))
        }
    }

    func testRefusesOldVersionAndNonRFB() {
        var a = RFBMachine()
        XCTAssertThrowsError(try a.receive(Data("RFB 003.003\n".utf8)))
        var b = RFBMachine()
        XCTAssertThrowsError(try b.receive(Data("HTTP/1.1 200 ".utf8)))
    }

    func testServerFailureReasonSurfaced() {
        var m = RFBMachine()
        let reason = "too many"
        XCTAssertThrowsError(try m.receive(Data("RFB 003.008\n".utf8) + Data([0] + be32(reason.utf8.count) + Array(reason.utf8)))) {
            XCTAssertEqual($0 as? RFBError, .refused("too many"))
        }
        var s = RFBMachine()
        XCTAssertThrowsError(try s.receive(Data("RFB 003.008\n".utf8) + Data([1, 1] + be32(1) + be32(3) + Array("bad".utf8)))) {
            XCTAssertEqual($0 as? RFBError, .refused("bad"))
        }
    }

    func testOversizedFramebufferRejected() {
        var m = RFBMachine()
        XCTAssertThrowsError(try m.receive(handshake(w: 8000, h: 8000))) { if case RFBError.limit = $0 {} else { XCTFail("\($0)") } }
        var z = RFBMachine()
        XCTAssertThrowsError(try z.receive(handshake(w: 0, h: 10)))
        var n = RFBMachine()   // hostile desktop-name length
        let bad = Data("RFB 003.008\n".utf8) + Data([1, 1] + be32(0)) + Data(be16(4) + be16(4) + [UInt8](repeating: 0, count: 16) + be32(1 << 30))
        XCTAssertThrowsError(try n.receive(bad))
    }

    func testRectOutsideFramebufferAndUnsupportedEncodingRejected() throws {
        var m = RFBMachine(); _ = try m.receive(handshake())
        XCTAssertThrowsError(try m.receive(Data([0, 0] + be16(1) + rect(x: 3, y: 0, w: 2, h: 1, enc: 0))))
        XCTAssertThrowsError(try m.receive(Data([0, 0, 0, 1])), "stays failed")
        var t = RFBMachine(); _ = try t.receive(handshake())
        XCTAssertThrowsError(try t.receive(Data([0, 0] + be16(1) + rect(x: 0, y: 0, w: 1, h: 1, enc: 7)))) {
            guard case RFBError.unsupported = $0 else { return XCTFail("\($0)") }
        }
        var c = RFBMachine(); _ = try c.receive(handshake())
        XCTAssertThrowsError(try c.receive(Data([0, 0] + be16(1) + rect(x: 0, y: 0, w: 2, h: 1, enc: 1) + be16(3) + be16(0))))
    }

    func testHostileHugeRectNeverAllocates() throws {
        var m = RFBMachine(); _ = try m.receive(handshake(w: 4096, h: 4096))
        // Declares a full 64 MiB Raw rect but sends only the header: must wait, not blow up, then be bounded.
        let out = try m.receive(Data([0, 0] + be16(1) + rect(x: 0, y: 0, w: 4096, h: 4096, enc: 0)))
        XCTAssertTrue(out.events.isEmpty)
        // Oversized clipboard announcement is rejected.
        var c = RFBMachine(); _ = try c.receive(handshake())
        XCTAssertThrowsError(try c.receive(Data([3, 0, 0, 0] + be32(1 << 28))))
        // Unknown message type.
        var u = RFBMachine(); _ = try u.receive(handshake())
        XCTAssertThrowsError(try u.receive(Data([99])))
    }

    func testInputEncoding() throws {
        var m = RFBMachine()
        XCTAssertNil(m.pointerEvent(x: 1, y: 1, buttons: 0), "no input before the handshake")
        _ = try m.receive(handshake())
        XCTAssertEqual(m.pointerEvent(x: 2, y: 1, buttons: 1), Data([5, 1, 0, 2, 0, 1]))
        XCTAssertEqual(m.pointerEvent(x: 99, y: -5, buttons: 0), Data([5, 0, 0, 3, 0, 0]))
        XCTAssertEqual(m.keyEvent(keysym: 0xFF0D, down: true), Data([4, 1, 0, 0, 0, 0, 0xFF, 0x0D]))
    }

    func testClientOverFakeTransport() async throws {
        let h = handshake()
        let update = Data([0, 0] + be16(1) + rect(x: 0, y: 0, w: 1, h: 1, enc: 0) + [1, 2, 3, 0])
        let t = FakeRFBTransport([h.prefix(20), h.dropFirst(20), update])
        let c = RFBClient(transport: t)
        let box = EventBox()
        try await c.run { e, _ in box.add(e) }
        XCTAssertEqual(box.events.count, 2)
        XCTAssertEqual(t.sent.first, Data("RFB 003.008\n".utf8))
        let fb = await c.framebuffer
        XCTAssertEqual(Array(fb.pixels.prefix(4)), [1, 2, 3, 0])
    }

    func testClientPropagatesRefusal() async {
        let t = FakeRFBTransport([Data("RFB 003.008\n".utf8) + Data([1, 2])])
        do { try await RFBClient(transport: t).run { _, _ in }; XCTFail("expected throw") }
        catch { XCTAssertTrue(error is RFBError) }
    }

    func testVNCPhraseAndGate() {
        XCTAssertEqual(ConsoleData.vncPhrase(namespace: "ns", name: "vm1"), "vnc ns/vm1")
        XCTAssertEqual(ConsoleData.vncDecision(whoami: nil, consoleEnabled: true, typed: "", namespace: "ns", name: "vm1"), .blocked(reason: "Not connected"))
    }
}

final class EventBox: @unchecked Sendable {
    private let lock = NSLock(); private var _e: [RFBMachine.Event] = []
    func add(_ e: RFBMachine.Event) { lock.lock(); _e.append(e); lock.unlock() }
    var events: [RFBMachine.Event] { lock.lock(); defer { lock.unlock() }; return _e }
}
