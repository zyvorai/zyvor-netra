// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import AppKit
import CoreSpotlight
import NetraKit
import SwiftUI

/// Routes deep links, Spotlight results and web-UI handoff. Navigation only: nothing here mutates controller state.
@MainActor @Observable
final class LinkRouter {
    static let shared = LinkRouter()
    /// Filter carried by the last link or palette choice, for pages that want to apply it.
    var pendingFilter: [String: String] = [:]
    var lastError: String?

    static let validSections = Set(NavSection.allCases.map(\.rawValue))

    func open(_ link: DeepLink, model: AppModel) {
        guard let s = NavSection(rawValue: link.section) else { return }
        pendingFilter = link.query
        lastError = nil
        model.selection = s
    }

    func open(url: URL, model: AppModel) {
        do { open(try DeepLink.parse(url, validSections: Self.validSections), model: model) }
        catch { lastError = "Ignored link: \(url.scheme ?? "?")://… (\(error))" }
    }

    func deepLink(for section: NavSection, filter: [String: String] = [:]) -> URL? {
        DeepLink(section: section.rawValue, query: filter).url
    }

    func webURL(model: AppModel, section: NavSection?, filter: [String: String] = [:]) -> URL? {
        guard let base = URL(string: model.baseURLText) else { return nil }
        return WebHandoff.url(base: base, section: (section ?? .overview).rawValue, query: filter)
    }

    /// "Open in web UI": hands the current section to the controller's browser UI.
    func openInWeb(model: AppModel, section: NavSection? = nil, filter: [String: String] = [:]) {
        if let u = webURL(model: model, section: section ?? model.selection, filter: filter) { NSWorkspace.shared.open(u) }
    }

    func copyDeepLink(section: NavSection, filter: [String: String] = [:]) {
        guard let u = deepLink(for: section, filter: filter) else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(u.absoluteString, forType: .string)
    }
}

private struct LinkRoutingModifier: ViewModifier {
    @Environment(AppModel.self) private var model

    func body(content: Content) -> some View {
        content
            .onOpenURL { LinkRouter.shared.open(url: $0, model: model) }
            // Spotlight result: the item identifier is a netra:// link.
            .onContinueUserActivity(CSSearchableItemActionType) { activity in
                if let id = activity.userInfo?[CSSearchableItemActivityIdentifier] as? String, let u = URL(string: id) {
                    LinkRouter.shared.open(url: u, model: model)
                }
            }
            // Handoff: advertise the current section as a web URL so another device can continue in a browser.
            .userActivity("dev.zyvor.netra.section", isActive: model.selection != nil) { activity in
                activity.title = "Netra: \((model.selection ?? .overview).title)"
                activity.isEligibleForHandoff = true
                activity.webpageURL = LinkRouter.shared.webURL(model: model, section: model.selection)
                activity.isEligibleForSearch = false
            }
            .onContinueUserActivity("dev.zyvor.netra.section") { activity in
                if let u = activity.webpageURL, let r = WebHandoff.parse(u),
                   let sec = NavSection.allCases.first(where: { WebHandoff.pages[$0.rawValue] == r.page }) {
                    LinkRouter.shared.open(DeepLink(section: sec.rawValue, query: r.query), model: model)
                }
            }
            .task { SpotlightIndexer.indexSections() }
    }
}

extension View {
    /// Handles `netra://` links, Spotlight results and Handoff. Requires AppModel in the environment.
    func linkRouting() -> some View { modifier(LinkRoutingModifier()) }
}
