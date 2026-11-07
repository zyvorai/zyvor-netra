// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

enum MorePages {
    @MainActor @ViewBuilder static func view(for section: NavSection) -> some View {
        switch section {
        case .tcpEvents: MoreTCPEventsPage()
        case .connections: MoreConnectionsPage()
        case .pathDiag: MorePathPage()
        case .congestion: MoreCongestionPage()
        case .ebpfCoverage: MoreCoveragePage()
        case .explain: MoreExplainPage()
        case .investigate: MoreInvestigatePage()
        default: JSONBrowserView(section: section).id(section)
        }
    }
}
