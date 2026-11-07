// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Bespoke views for: workloads, pods, l7, tls, diagnostics. All read-only (the lockdown flow lives in Policies).
/// Anything not built here falls back to the JSON browser.
enum WorkloadPages {
    @MainActor @ViewBuilder static func view(for section: NavSection) -> some View {
        switch section {
        case .workloads: WorkloadsPage()
        case .pods: PodsPage()
        case .l7: L7Page()
        case .tls: TLSPage()
        case .diagnostics: DiagnosticsPage()
        default: JSONBrowserView(section: section).id(section)
        }
    }
}
