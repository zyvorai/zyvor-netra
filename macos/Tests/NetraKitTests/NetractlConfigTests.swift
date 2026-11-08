// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class NetractlConfigTests: XCTestCase {
    func testParsesEnvFileWithExportQuotesAndComments() {
        let text = """
        # written by deploy-remote
        export NETRA_URL="https://10.0.1.5:30870"
        export NETRA_API_KEY='abc123'
        NETRA_TLS_INSECURE=true
        """
        let c = NetractlConfig.parse(text)
        XCTAssertEqual(c.url, "https://10.0.1.5:30870")
        XCTAssertEqual(c.apiKey, "abc123")
        XCTAssertTrue(c.requestedInsecureTLS)
    }

    func testBareApiKeyFile() {
        let c = NetractlConfig.parse("  s3cr3t-key \n")
        XCTAssertEqual(c.apiKey, "s3cr3t-key")
        XCTAssertNil(c.url)
    }

    func testRejectsNonHTTPURLAndPlainProse() {
        XCTAssertNil(NetractlConfig.parse("NETRA_URL=ftp://host").url)
        XCTAssertNil(NetractlConfig.parse("NETRA_URL=notaurl").url)
        XCTAssertTrue(NetractlConfig.parse("this is a sentence, not a key").isEmpty)
        XCTAssertTrue(NetractlConfig.parse("").isEmpty)
    }

    func testAssignmentsWithoutKnownKeysAreNotTakenAsApiKey() {
        XCTAssertTrue(NetractlConfig.parse("FOO=bar").isEmpty)
    }

    func testMergeFillsOnlyGaps() {
        let a = NetractlConfig(url: "https://a:30870")
        let b = NetractlConfig(url: "https://b:30870", apiKey: "k")
        let m = NetractlConfig.merge([a, b])
        XCTAssertEqual(m.url, "https://a:30870")
        XCTAssertEqual(m.apiKey, "k")
    }

    func testInsecureFlagIsReportedNotHonoured() {
        XCTAssertFalse(NetractlConfig.parse("NETRA_URL=https://h:1").requestedInsecureTLS)
        XCTAssertTrue(NetractlConfig.parse("NETRA_TLS_INSECURE=1").requestedInsecureTLS)
    }
}
