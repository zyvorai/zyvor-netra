// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Metrics, Anomalies and Alerts pages. Observe-only: the only writes are alert ack and silences,
/// which change notification state and nothing else.
struct MetricsView: View {
    var section: NavSection = .metrics
    var body: some View {
        switch section {
        case .anomalies: AnomaliesPage()
        case .alerts: AlertsPage()
        default: MetricsChartPage()
        }
    }
}
