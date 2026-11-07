// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

@preconcurrency import CoreSpotlight
import Foundation
import NetraKit
import UniformTypeIdentifiers

/// Core Spotlight index of section shortcuts and recently seen incident/pod titles.
/// Titles only: never payloads, command lines or secrets. Each item's identifier is a `netra://` deep link,
/// so choosing a result is routed through the same strict parser as any other link.
enum SpotlightIndexer {
    static let sectionDomain = "dev.zyvor.netra.section"
    static let recentDomain = "dev.zyvor.netra.recent"

    /// A bare SwiftPM executable has no bundle identifier and CoreSpotlight would misbehave; skip quietly.
    static var available: Bool { Bundle.main.bundleIdentifier != nil && CSSearchableIndex.isIndexingAvailable() }

    private static func item(id: String, title: String, description: String, keywords: [String], domain: String) -> CSSearchableItem {
        let a = CSSearchableItemAttributeSet(contentType: .item)
        a.title = title
        a.contentDescription = description
        a.keywords = keywords
        return CSSearchableItem(uniqueIdentifier: id, domainIdentifier: domain, attributeSet: a)
    }

    static func indexSections() {
        guard available else { return }
        let items = NavSection.allCases.compactMap { s -> CSSearchableItem? in
            guard let u = DeepLink(section: s.rawValue).url else { return nil }
            return item(id: u.absoluteString, title: "Netra: \(s.title)", description: "Open \(s.title) in Netra",
                        keywords: ["netra", s.title], domain: sectionDomain)
        }
        replace(domain: sectionDomain, with: items)
    }

    /// Recently seen titles; capped so the index stays small.
    static func indexRecent(_ objects: [PaletteObject]) {
        guard available else { return }
        let wanted = objects.filter { $0.kind == .incident || $0.kind == .pod }
        let items = (wanted.filter { $0.kind == .incident }.prefix(25) + wanted.filter { $0.kind == .pod }.prefix(50)).compactMap { o -> CSSearchableItem? in
            guard let u = DeepLink(section: o.section, query: o.query).url else { return nil }
            return item(id: u.absoluteString, title: o.title, description: "\(o.kind.label) · \(o.subtitle)",
                        keywords: ["netra", o.kind.rawValue], domain: recentDomain)
        }
        replace(domain: recentDomain, with: Array(items))
    }

    static func removeAll() {
        guard available else { return }
        CSSearchableIndex.default().deleteSearchableItems(withDomainIdentifiers: [sectionDomain, recentDomain]) { _ in }
    }

    private static func replace(domain: String, with items: [CSSearchableItem]) {
        let index = CSSearchableIndex.default()
        index.deleteSearchableItems(withDomainIdentifiers: [domain]) { _ in
            index.indexSearchableItems(items) { _ in }
        }
    }
}
