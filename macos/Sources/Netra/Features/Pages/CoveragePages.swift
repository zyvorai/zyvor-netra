// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Read-only views for GET routes no other page reads: insight detail tabs, process watches, datapath detail,
/// fleet flow history and metric exporters.
enum CoveragePages {
    @MainActor @ViewBuilder static func view(for section: NavSection) -> some View {
        switch section {
        case .insightsDetail: CovInsightsPage().id(section)
        case .processWatch: CovProcessPage().id(section)
        case .datapathDetail: CovDatapathPage().id(section)
        case .fleetExporters: CovFleetPage().id(section)
        default: JSONBrowserView(section: section).id(section)
        }
    }
}
