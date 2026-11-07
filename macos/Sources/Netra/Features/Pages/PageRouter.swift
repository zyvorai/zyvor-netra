// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Sends each sidebar section to the group file that owns it. Each group's `view(for:)` falls back to the
/// generic JSON browser for sections it has not built yet.
struct PageRouter: View {
    let section: NavSection
    var body: some View {
        switch section {
        case .health, .scorecard, .slo, .audit, .compliance, .report: NowPages.view(for: section)
        case .talkers, .ports, .protocols, .drops, .dns: TrafficPages.view(for: section)
        case .workloads, .pods, .l7, .tls, .diagnostics: WorkloadPages.view(for: section)
        case .listenQueues, .sysctl, .nodeResources, .netlink, .attachments, .maps: KernelPages.view(for: section)
        case .insights, .incidents, .security, .intel: DetectPages.view(for: section)
        case .aiBrief, .aiDigest, .aiSuggestions, .fleet: AskPages.view(for: section)
        case .tcpEvents, .connections, .pathDiag, .congestion, .ebpfCoverage, .explain, .investigate: MorePages.view(for: section)
        case .optimizer, .playbooks, .baselines, .agents, .surfaces: PlatformPages.view(for: section)
        case .metricContexts: MetricsPages.view(for: section)
        case .exports, .artifacts, .gitops, .tenants: OpsPages.view(for: section)
        default: JSONBrowserView(section: section).id(section)
        }
    }
}
