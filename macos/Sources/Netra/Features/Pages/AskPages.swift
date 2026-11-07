// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Bespoke views for: aiBrief, aiDigest, aiSuggestions, fleet.
/// Return nil for a section this group does not own (or has not built yet): the router falls back to the JSON browser.
enum AskPages {
    @MainActor @ViewBuilder static func view(for section: NavSection) -> some View {
        switch section {
        case .aiBrief, .aiDigest, .aiSuggestions: AIPage(section: section).id(section)
        case .fleet: FleetPage()
        default: JSONBrowserView(section: section).id(section)
        }
    }
}
