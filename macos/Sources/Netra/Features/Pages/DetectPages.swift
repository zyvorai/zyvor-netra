// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Bespoke views for: insights, incidents, security, intel. All read-only.
/// Anything else falls through to the generic JSON browser.
enum DetectPages {
    @MainActor @ViewBuilder static func view(for section: NavSection) -> some View {
        switch section {
        case .insights: InsightsPage().id(section)
        case .incidents: IncidentsPage().id(section)
        case .security: SecurityPage().id(section)
        case .intel: IntelPage().id(section)
        default: JSONBrowserView(section: section).id(section)
        }
    }
}
