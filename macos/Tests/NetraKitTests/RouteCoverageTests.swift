// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import XCTest
import Foundation
@testable import NetraKit

/// Backs macos/route-dynamic.txt: routes the app builds dynamically (RuleKinds, OpsData) are not
/// greppable, so this test enumerates every kind/action/removal and asserts the exact set of
/// (verb, path) pairs the builders produce equals the entries in that file.
final class RouteCoverageTests: XCTestCase {
    private func client() -> NetraClient {
        NetraClient(profile: .init(baseURL: URL(string: "http://stub.invalid")!, token: "t"))
    }

    /// A valid draft for the kind with recognisable values, so path segments can be mapped to {ip}/{uid}.
    private func draft(_ kind: RuleKind, _ action: RuleAction, removing: Bool) -> RuleDraft {
        var d = RuleDraft(); d.kind = kind; d.action = action; d.removing = removing
        switch kind {
        case .ip, .synDrop, .rate: d.value = "192.0.2.7"
        case .cidr, .synDropCIDR: d.value = "10.0.0.0/8"
        case .port: d.port = 8080
        case .uid: d.value = "1234"
        case .dns, .sni: d.value = "example.com"
        case .process: d.value = "curl"
        case .capability: d.value = "CAP_NET_ADMIN"
        case .exeHash: d.value = String(repeating: "ab", count: 32)
        }
        if kind == .rate { d.pps = 100 }
        return d
    }

    private func norm(_ r: URLRequest) -> String {
        var p = r.url!.path
        p = p.replacingOccurrences(of: "192.0.2.7", with: "{ip}").replacingOccurrences(of: "/1234", with: "/{uid}")
        return "\(r.httpMethod!) \(p)"
    }

    private func ruleRoutes() -> Set<String> {
        var out = Set<String>()
        for kind in RuleKind.allCases {
            for action in RuleAction.allCases {
                for removing in [false, true] {
                    let d = draft(kind, action, removing: removing)
                    if action == .allow && !kind.supportsAllow {
                        XCTAssertNotNil(d.validationError, "\(kind) must reject allow")
                        continue
                    }
                    XCTAssertNil(d.validationError, "\(kind)/\(action)/\(removing)")
                    out.insert(norm(d.mutationRequest(client())))
                }
            }
        }
        return out
    }

    private func exportRoutes() -> Set<String> {
        Set(OpsExportKind.allCases.map { "GET /" + $0.path })
    }

    /// Entries of route-dynamic.txt grouped by their builder comment.
    private func fileEntries() throws -> [String: Set<String>] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("route-dynamic.txt")
        let text = try String(contentsOf: url, encoding: .utf8)
        var out: [String: Set<String>] = [:]
        for raw in text.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let parts = line.components(separatedBy: "#")
            let route = parts[0].split(separator: " ").joined(separator: " ")
            let builder = parts.count > 1 ? parts[1].replacingOccurrences(of: "builder:", with: "").trimmingCharacters(in: .whitespaces) : ""
            out[builder, default: []].insert(route)
        }
        return out
    }

    func testRuleKindsProduceExactlyTheListedRoutes() throws {
        let listed = try fileEntries()["RuleKinds.swift"] ?? []
        let built = ruleRoutes()
        XCTAssertEqual(built, listed, "only in builder: \(built.subtracting(listed).sorted()); only in file: \(listed.subtracting(built).sorted())")
        XCTAssertTrue(built.contains("PUT /api/v1/ebpf/rate"))
        XCTAssertTrue(built.contains("DELETE /api/v1/ebpf/rate/{ip}"))
        XCTAssertTrue(built.contains("POST /api/v1/ebpf/allow-cidr/delete"))
        XCTAssertFalse(built.contains("POST /api/v1/ebpf/allow-uid/delete"), "uid removal is DELETE-only")
    }

    func testOpsExportProducesExactlyTheListedRoutes() throws {
        let listed = try fileEntries()["OpsData.swift"] ?? []
        XCTAssertEqual(exportRoutes(), listed)
    }

    func testNoUnlistedBuilderEntries() throws {
        let all = try fileEntries()
        XCTAssertEqual(Set(all.keys), ["RuleKinds.swift", "OpsData.swift"])
    }
}
