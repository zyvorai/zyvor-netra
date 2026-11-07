// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation
import XCTest
@testable import NetraKit

final class ConsoleDataTests: XCTestCase {
    private func who(_ role: String) -> WhoAmI { WhoAmI(authRequired: true, oidcEnabled: false, kind: "key", role: role, identity: nil) }

    func testPathsAndQuery() {
        XCTAssertEqual(ConsoleData.execPath(namespace: "kube-system", name: "a b"), "api/v1/pods/kube-system/a%20b/exec")
        XCTAssertEqual(ConsoleData.vncPath(namespace: "n", name: "vm"), "api/v1/vms/n/vm/vnc")
        XCTAssertEqual(ConsoleData.execQuery(container: "app").map(\.name), ["command", "container"])
        XCTAssertEqual(ConsoleData.execQuery(container: "").count, 1)
    }

    func testWebSocketURL() {
        XCTAssertEqual(ConsoleData.webSocketURL(URL(string: "https://h:8443/x")!).absoluteString, "wss://h:8443/x")
        XCTAssertEqual(ConsoleData.webSocketURL(URL(string: "http://h/x")!).scheme, "ws")
    }

    func testResizeAndStatus() {
        XCTAssertEqual(ConsoleData.resizeMessage(cols: 120, rows: 30), "{\"type\":\"resize\",\"cols\":120,\"rows\":30}")
        XCTAssertEqual(ConsoleData.resizeMessage(cols: 0, rows: 5000), "{\"type\":\"resize\",\"cols\":1,\"rows\":1000}")
        XCTAssertTrue(ConsoleData.consoleEnabled(fromStatus: Data(#"{"consoleEnabled":true}"#.utf8)))
        XCTAssertFalse(ConsoleData.consoleEnabled(fromStatus: Data(#"{"x":1}"#.utf8)))
        XCTAssertFalse(ConsoleData.consoleEnabled(fromStatus: Data("nope".utf8)))
    }

    func testAvailability() {
        XCTAssertEqual(ConsoleData.availability(consoleEnabled: true, whoami: who("admin")), .allowed)
        XCTAssertNotEqual(ConsoleData.availability(consoleEnabled: false, whoami: who("admin")), .allowed)
        XCTAssertNotEqual(ConsoleData.availability(consoleEnabled: nil, whoami: who("admin")), .allowed)
        XCTAssertNotEqual(ConsoleData.availability(consoleEnabled: true, whoami: who("viewer")), .allowed)
        XCTAssertNotEqual(ConsoleData.availability(consoleEnabled: true, whoami: who("operator")), .allowed)
        XCTAssertNotEqual(ConsoleData.availability(consoleEnabled: true, whoami: nil), .allowed)
    }

    func testExecDecisionNeedsTypedPhrase() {
        let d = { (t: String) in ConsoleData.execDecision(whoami: self.who("admin"), consoleEnabled: true, typed: t, namespace: "ns", name: "p") }
        XCTAssertEqual(d("exec ns/p"), .allowed(confirmRiskHeader: true))
        XCTAssertEqual(d("exec ns/x"), .needsTypedConfirmation(phrase: "exec ns/p"))
        if case .blocked = ConsoleData.execDecision(whoami: who("viewer"), consoleEnabled: true, typed: "exec ns/p", namespace: "ns", name: "p") {} else { XCTFail() }
    }

    func testClassify() {
        XCTAssertEqual(ConsoleData.classify(textFrame: "exec error: boom\r\n"), .execError("boom"))
        XCTAssertEqual(ConsoleData.classify(textFrame: "\r\n[exec] {\"status\":\"Success\"}"), .execStatus("{\"status\":\"Success\"}"))
        XCTAssertEqual(ConsoleData.classify(textFrame: "hi"), .none)
    }

    func testUTF8SplitAcrossChunks() {
        var d = ConsoleUTF8Decoder()
        let bytes = Array("a€b".utf8)  // € = 3 bytes
        XCTAssertEqual(d.feed(Data(bytes[0..<2])), "a")
        XCTAssertEqual(d.feed(Data(bytes[2..<3])), "")
        XCTAssertEqual(d.feed(Data(bytes[3...])), "€b")
    }

    func testScreenStripsANSIAndHandlesCR() {
        var s = ConsoleScreen()
        s.feed("\u{1B}[32mgreen\u{1B}[0m\r\nab\u{8}c\r\n")
        s.feed("\u{1B}]0;title\u{07}x\u{1B}[3")  // split CSI
        s.feed("1mY\u{1B}[0m\rZ")
        XCTAssertEqual(s.text, "green\nac\nZY")
    }

    func testScreenEraseAndCap() {
        var s = ConsoleScreen(maxLines: 2)
        s.feed("hello\r\u{1B}[K!\n1\n2\n3\n")
        XCTAssertEqual(s.lines, ["2", "3"])
        var t = ConsoleScreen()
        t.feed("hello\r\u{1B}[Kx")
        XCTAssertEqual(t.text, "x")
    }
}
