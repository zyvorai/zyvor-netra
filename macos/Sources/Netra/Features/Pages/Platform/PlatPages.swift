// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Shared one-line banner under the stat cards.
struct PlatNote: View {
    let text: String
    var symbol = "info.circle"
    var body: some View {
        if !text.isEmpty {
            Label(text, systemImage: symbol).font(.caption).foregroundStyle(.secondary)
                .padding(.horizontal).padding(.bottom, 6).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private func count(_ v: JSONValue, _ path: String) -> Int { if case .array(let a)? = v.at(path) { a.count } else { 0 } }

/// Deny-rule overlap suggestions. Review only: the controller never applies them.
struct PlatOptimizerPage: View {
    var body: some View {
        DataPageView(PageConfig(
            title: "Optimizer", endpoint: "api/v1/security/optimizer", rowsPath: "suggestions",
            idKeys: ["rule", "kind"],
            columns: [
                .init(title: "Kind", path: "kind", width: 110),
                .init(title: "Rule", path: "rule", width: 160),
                .init(title: "Related rule", path: "relatedRule", width: 160),
                .init(title: "Suggestion", path: "message", width: 320),
            ],
            stats: [
                .init(title: "Rules reviewed", symbol: "list.bullet") { $0.at("totalRules")?.asDouble.map { String(Int($0)) } ?? "0" },
                .init(title: "Suggestions", symbol: "lightbulb", tint: .orange) { String(count($0, "suggestions")) },
                .init(title: "Truncated", symbol: "scissors") { if case .bool(true)? = $0.at("truncated") { "yes" } else { "no" } },
            ],
            emptyText: "No overlapping or redundant deny rules found."
        )) { v in
            PlatNote(text: DetectData.str(v, "note").isEmpty ? "Read-only review: suggestions are never applied automatically." : DetectData.str(v, "note"), symbol: "eye")
        }
    }
}

/// Operator playbook steps. Commands are shown as text to copy; nothing is run from here.
struct PlatPlaybooksPage: View {
    var body: some View {
        DataPageView(PageConfig(
            title: "Playbooks", endpoint: "api/v1/playbooks", rowsPath: "steps", idKeys: ["id"],
            columns: [
                .init(title: "Severity", path: "severity", width: 80),
                .init(title: "Step", path: "title", width: 220),
                .init(title: "Why", path: "rationale", width: 300),
                .init(title: "Command", path: "command", width: 220),
                .init(title: "API", path: "api", width: 160),
                .init(title: "Review only", path: "reviewOnly", kind: .bool, width: 90),
            ],
            stats: [
                .init(title: "Steps", symbol: "list.number") { String(count($0, "steps")) },
                .init(title: "Review only", symbol: "eye") {
                    String($0.rows(at: "steps").filter { if case .bool(true)? = $0.value["reviewOnly"] { true } else { false } }.count)
                },
            ],
            emptyText: "No playbook steps right now. Nothing needs attention."
        )) { v in
            let h = DetectData.str(v, "headline")
            if !h.isEmpty { Text(h).font(.headline).padding(.horizontal).padding(.bottom, 6).frame(maxWidth: .infinity, alignment: .leading) }
        }
    }
}

/// Registered agents (one row per node) from GET /agents ({items:[AgentStatus], staleAfterSeconds}).
/// `interfaces` and `hooks` are string arrays, so they are joined into `...Text` fields for the table.
struct PlatAgentsPage: View {
    var body: some View {
        MoreLoader(title: "Agents", endpoint: "api/v1/agents", liveEvery: 5) { v, _ in
            VStack(spacing: 0) {
                StatRow(stats: [
                    .init(title: "Agents", symbol: "antenna.radiowaves.left.and.right") { String(PlatformData.agentCounts($0).total) },
                    .init(title: "Stale", symbol: "exclamationmark.triangle", tint: .orange) { String(PlatformData.agentCounts($0).stale) },
                    .init(title: "Enforcing", symbol: "shield.lefthalf.filled", tint: .red) { String(PlatformData.agentCounts($0).enforcing) },
                    .init(title: "Stale after", symbol: "clock") { CellFormat.duration(PlatformData.agentCounts($0).staleAfter) },
                ], value: v).padding([.horizontal, .top])
                MoreRowsTable(rows: MoreData.defaultingFalse(MoreData.joined(MoreData.joined(v.rows(at: "items", idKeys: ["node"]), key: "interfaces"), key: "hooks"), keys: ["mtls"]), columns: [
                    .init(title: "Node", path: "node", width: 160),
                    .init(title: "Mode", path: "mode", width: 80),
                    .init(title: "Stale", path: "stale", kind: .bool, width: 60),
                    .init(title: "Last report", path: "ageSeconds", kind: .seconds, width: 90),
                    .init(title: "Interfaces", path: "interfacesText", width: 160),
                    .init(title: "Hooks", path: "hooksText", width: 220),
                    .init(title: "mTLS", path: "mtls", kind: .bool, width: 60),
                    .init(title: "Standalone", path: "standalone", kind: .bool, width: 80),
                ], empty: "No agents have reported yet.")
            }
        }
    }
}
