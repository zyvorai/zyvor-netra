// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import AppIntents
import AppKit
import Foundation
import NetraKit

/// Read-only Shortcuts. Every intent performs GETs only, through NetraClient with the active profile's stored
/// token. There are deliberately no intents that change mode, lease, rules or policy.
enum IntentClient {
    struct NotConfigured: Error, CustomLocalizedStringResourceConvertible {
        var localizedStringResource: LocalizedStringResource { "Netra has no configured server. Open Netra and connect first." }
    }
    static func make() throws -> NetraClient {
        let store = ProfileStore()
        guard let p = store.active(), let url = p.url, url.scheme != nil else { throw NotConfigured() }
        let profile = ConnectionProfile(baseURL: url, token: store.token(for: p))
        return url.scheme == "https" ? NetraClient.pinned(profile: profile, pinStore: PinStore()) : NetraClient(profile: profile)
    }
}

struct GetModeAndLeaseIntent: AppIntent {
    static let title: LocalizedStringResource = "Get Netra Mode and Lease"
    static let description = IntentDescription("Reports the controller's mode and lease state. Read-only.")
    func perform() async throws -> some IntentResult & ReturnsValue<String> & ProvidesDialog {
        let text = IntentSummaries.modeAndLease(try await IntentClient.make().lease())
        return .result(value: text, dialog: IntentDialog(stringLiteral: text))
    }
}

struct CountActiveAlertsIntent: AppIntent {
    static let title: LocalizedStringResource = "Count Active Netra Alerts"
    static let description = IntentDescription("Counts raised, unsilenced metric alerts. Read-only: nothing is acknowledged.")
    func perform() async throws -> some IntentResult & ReturnsValue<Int> & ProvidesDialog {
        let snap = try await IntentClient.make().metricsAlerts(all: false, history: 0)
        return .result(value: IntentSummaries.activeAlertCount(snap),
                       dialog: IntentDialog(stringLiteral: IntentSummaries.alertSummary(snap)))
    }
}

struct ShowTopTalkersIntent: AppIntent {
    static let title: LocalizedStringResource = "Show Netra Top Talkers"
    static let description = IntentDescription("Lists the busiest destinations. Read-only.")
    @Parameter(title: "Count", default: 5, inclusiveRange: (1, 20)) var count: Int
    func perform() async throws -> some IntentResult & ReturnsValue<String> & ProvidesDialog {
        let v = try await IntentClient.make().json("api/v1/talkers")
        let text = IntentSummaries.topTalkers(TrafficData.talkerBars(v, top: count), limit: count)
        return .result(value: text, dialog: IntentDialog(stringLiteral: text))
    }
}

enum NetraSectionChoice: String, AppEnum {
    case overview, health, flows, talkers, drops, alerts, anomalies, lease
    static let typeDisplayRepresentation: TypeDisplayRepresentation = "Netra Section"
    static let caseDisplayRepresentations: [NetraSectionChoice: DisplayRepresentation] = [
        .overview: "Overview", .health: "Health", .flows: "Flows", .talkers: "Talkers",
        .drops: "Drops", .alerts: "Alerts", .anomalies: "Anomalies", .lease: "Lease",
    ]
}

/// Navigation only: hands a netra:// deep link to the app, which routes it through LinkRouter.
struct OpenNetraSectionIntent: AppIntent {
    static let title: LocalizedStringResource = "Open Netra Section"
    static let description = IntentDescription("Opens a section of the Netra app. Navigation only.")
    static let openAppWhenRun = true
    @Parameter(title: "Section") var section: NetraSectionChoice
    @MainActor func perform() async throws -> some IntentResult {
        if let url = DeepLink(section: section.rawValue, query: [:]).url { NSWorkspace.shared.open(url) }
        return .result()
    }
}

struct NetraShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: GetModeAndLeaseIntent(), phrases: ["Get \(.applicationName) mode and lease"],
                    shortTitle: "Mode and Lease", systemImageName: "shield.lefthalf.filled")
        AppShortcut(intent: CountActiveAlertsIntent(), phrases: ["Count \(.applicationName) alerts"],
                    shortTitle: "Active Alerts", systemImageName: "bell.badge")
        AppShortcut(intent: ShowTopTalkersIntent(), phrases: ["Show \(.applicationName) top talkers"],
                    shortTitle: "Top Talkers", systemImageName: "person.2.wave.2")
        AppShortcut(intent: OpenNetraSectionIntent(), phrases: ["Open \(.applicationName) section"],
                    shortTitle: "Open Section", systemImageName: "sidebar.left")
    }
}
