// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
@testable import NetraKit

final class OpsDataTests: XCTestCase {
    private func json(_ s: String) -> JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(s.utf8)) }

    func testExportQueryClampsLimit() {
        let q = OpsData.exportQuery(format: .otlpTrace, limit: 99999, kind: .blocks)
        XCTAssertEqual(q.first { $0.name == "format" }?.value, "otlp-trace")
        XCTAssertEqual(q.first { $0.name == "limit" }?.value, "2000")
        XCTAssertEqual(OpsData.exportQuery(format: .json, limit: 0, kind: .audit).last?.value, "1")
        XCTAssertEqual(OpsExportKind.audit.path, "api/v1/export/audit")
    }

    func testExportFilename() {
        let n = OpsData.exportFilename(kind: .flows, format: .jsonl, date: Date(timeIntervalSince1970: 0))
        XCTAssertEqual(n, "netra-flows-19700101-000000.jsonl")
    }

    func testArtifactRowsOnlyThoseWithArtifacts() {
        let v = json(#"{"entries":[{"node":"a","startedAt":"t"},{"node":"b","artifactId":"x1","contextAvailable":true}]}"#)
        let rows = OpsData.artifactRows(fromHistory: v)
        XCTAssertEqual(rows.count, 1); XCTAssertEqual(rows[0].text("artifactId"), "x1")
    }

    func testSummaryRowsTagState() {
        let v = json(#"{"active":[{"node":"a","summary":{"frames":5}}],"history":[{"node":"b"}]}"#)
        let rows = OpsData.summaryRows(v)
        XCTAssertEqual(rows.map { $0.text("state") }, ["active", "ended"])
        XCTAssertEqual(rows[0].text("frames"), "5")
    }

    func testGitOpsStatusParse() {
        let s = GitOpsStatus(json(#"{"lastRun":"t","dir":"/g","autoApply":true,"manifests":[{"path":"a.yaml","namespace":"n","name":"p","drifted":true,"applied":false,"plan":{"risk":"high"},"manifest":{"metadata":{"name":"p"}}}],"loadErrors":["bad"]}"#))
        XCTAssertTrue(s.autoApply); XCTAssertEqual(s.loadErrors, ["bad"])
        XCTAssertEqual(s.manifests.first?.risk, "high"); XCTAssertTrue(s.manifests[0].drifted)
        XCTAssertNotNil(s.manifests[0].manifestJSON)
    }

    func testArtifactIDSafety() {
        XCTAssertTrue(OpsData.isSafeArtifactID("auto-1700_abc"))
        XCTAssertFalse(OpsData.isSafeArtifactID("../x")); XCTAssertFalse(OpsData.isSafeArtifactID("a/b")); XCTAssertFalse(OpsData.isSafeArtifactID(""))
    }
}
