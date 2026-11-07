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

    var id: String {
        switch self {
        case .section(let s): "section|\(s.rawValue)"
        case .object(let o): o.id
        case .openWeb: "cmd|web"
        case .copyLink: "cmd|link"
        }
    }
    var title: String {
        switch self {
        case .section(let s): s.title
        case .object(let o): o.title
        case .openWeb: "Open in web UI"
        case .copyLink: "Copy deep link"
        }
    }
    var subtitle: String {
        switch self {
        case .section: "Section"
        case .object(let o): ([o.kind.label] + (o.subtitle.isEmpty ? [] : [o.subtitle])).joined(separator: " · ")
        case .openWeb: "Command · current page in the controller's browser UI"
        case .copyLink: "Command · netra:// link to the current page"
        }
    }
    var symbol: String {
        switch self {
        case .section(let s): s.symbol
        case .object(let o): o.kind.symbol
        case .openWeb: "safari"
        case .copyLink: "link"
        }
    }
}

/// Loads read-only objects for the palette once per presentation. Failures leave that kind empty.
@MainActor @Observable
final class PaletteStore {
    var objects: [PaletteObject] = []
    var loading = false

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

    /// Commands and sections first (they are what an empty query lists), then matching objects.
    func entries(query: String) -> [PaletteEntry] {
        let q = query.trimmingCharacters(in: .whitespaces)
        let sections = FuzzyMatch.rank(NavSection.allCases, query: q) { [$0.title, $0.rawValue] }.map { PaletteEntry.section($0.item) }
        let commands = FuzzyMatch.rank([PaletteEntry.openWeb, .copyLink], query: q) { [$0.title] }.map(\.item)
        return commands + sections + PaletteObjects.search(objects, query: q).map { PaletteEntry.object($0) }
    }
}
