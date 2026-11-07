// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

struct FlowsView: View {
    @State private var tab: FlowsTab = .live

    var body: some View {
        VStack(spacing: 0) {
            Picker("", selection: $tab) { ForEach(FlowsTab.allCases) { Text($0.rawValue).tag($0) } }
                .pickerStyle(.segmented).labelsHidden().frame(maxWidth: 320).padding(8)
            Divider()
            switch tab {
            case .live: FlowsLiveView()
            case .history: FlowsHistoryView()
            case .summary: FlowsSummaryView()
            }
        }
        .navigationTitle("Flows")
    }
}
