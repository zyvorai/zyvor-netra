// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Bespoke views for: health, scorecard, slo, audit, compliance, report. All read-only.
enum NowPages {
    @MainActor @ViewBuilder static func view(for section: NavSection) -> some View {
        switch section {
        case .health: HealthPage().id(section)
        case .scorecard: ScorecardPage().id(section)
        case .slo: SLOPage().id(section)
        case .audit: AuditPage().id(section)
        case .compliance: CompliancePage().id(section)
        case .report: ReportPage().id(section)
        default: JSONBrowserView(section: section).id(section)
        }
    }
}
