// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import NetraKit
import SwiftUI

/// What a palette row does when chosen. All actions are navigation or clipboard/browser handoff, never a mutation.
enum PaletteEntry: Identifiable, Hashable {
    case section(NavSection)
    case object(PaletteObject)
    case openWeb
    case copyLink
    /// Parsed natural-language query -> section + read-only filters.
    case intent(QueryIntent)
    /// A previously typed query; choosing it refills the field.
    case recent(String)
    /// Opens the Ask page with the text prefilled. Never sends anything by itself.
    case askAI(String)

    var id: String {
        switch self {
        case .section(let s): "section|\(s.rawValue)"
        case .object(let o): o.id
        case .openWeb: "cmd|web"
        case .copyLink: "cmd|link"
        case .intent(let i): i.id
        case .recent(let t): "recent|\(t)"
        case .askAI(let t): "ask|\(t)"
        }
    }
    var title: String {
        switch self {
        case .section(let s): s.title
        case .object(let o): o.title
        case .openWeb: "Open in web UI"
        case .copyLink: "Copy deep link"
        case .intent(let i): i.summary
        case .recent(let t): t
        case .askAI(let t): AskFallback.title(for: t)
        }
    }
    var subtitle: String {
        switch self {
        case .section: "Section"
        case .object(let o): ([o.kind.label] + (o.subtitle.isEmpty ? [] : [o.subtitle])).joined(separator: " · ")
        case .openWeb: "Command · current page in the controller's browser UI"
        case .copyLink: "Command · netra:// link to the current page"
        case .intent(let i): i.window == nil ? "Go to · filtered view" : "Go to · filtered view (time window is shown, not applied)"
        case .recent: "Recent query"
        case .askAI: "Opens Ask Netra, prefilled. Read-only; press Ask to send"
        }
    }
    var symbol: String {
        switch self {
        case .section(let s): s.symbol
        case .object(let o): o.kind.symbol
        case .openWeb: "safari"
        case .copyLink: "link"
        case .intent: "arrow.turn.down.right"
        case .recent: "clock.arrow.circlepath"
        case .askAI: "sparkles"
        }
    }
}

/// Loads read-only objects for the palette once per presentation. Failures leave that kind empty.
@MainActor @Observable
final class PaletteStore {
    var objects: [PaletteObject] = []
    var loading = false
    let recents = RecentQueries()
    private static let sectionIDs = Set(NavSection.allCases.map(\.rawValue))

    func load(client: NetraClient?) async {
        guard let client else { return }
        loading = true
        defer { loading = false }
        async let pods = try? client.json("api/v1/pods")
        async let workloads = try? client.json("api/v1/ebpf/workloads")
        async let talkers = try? client.json("api/v1/talkers")
        async let rules = try? client.json("api/v1/ebpf/rules")
        async let incidents = try? client.json("api/v1/incidents")
        let (p, w, t, r, i) = await (pods, workloads, talkers, rules, incidents)
        objects = PaletteObjects.incidents(i) + PaletteObjects.pods(p) + PaletteObjects.workloads(w)
            + PaletteObjects.rules(r) + PaletteObjects.ips([p, t])
        SpotlightIndexer.indexRecent(objects)
    }

    /// Typed text: parsed intent first, then commands, sections, matching objects, recents and finally the optional AI row.
    /// An empty query lists recent queries, commands and sections.
    func entries(query: String) -> [PaletteEntry] {
        let q = query.trimmingCharacters(in: .whitespaces)
        let sections = FuzzyMatch.rank(NavSection.allCases, query: q) { [$0.title, $0.rawValue] }.map { PaletteEntry.section($0.item) }
        let commands = FuzzyMatch.rank([PaletteEntry.openWeb, .copyLink], query: q) { [$0.title] }.map(\.item)
        let objs = PaletteObjects.search(objects, query: q).map { PaletteEntry.object($0) }
        let recent = recents.matching(q).filter { $0.caseInsensitiveCompare(q) != .orderedSame }.map { PaletteEntry.recent($0) }
        if q.isEmpty { return recent + commands + sections }
        var out: [PaletteEntry] = []
        if let i = QueryIntentParser.parse(q, validSections: Self.sectionIDs) { out.append(.intent(i)) }
        out += commands + sections + objs + recent.prefix(3)
        if AskFallback.shouldOffer(q) { out.append(.askAI(q)) }
        return out
    }
}
