// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation
import Observation
import UserNotifications
import NetraKit

/// Native notifications for new metric alerts, incidents, intel hits and lease expiry.
/// Read-only polling. The only action offered is Acknowledge on a metric alert, which goes through the
/// guarded `MetricAlertActions.ack` flow and changes notification state only. Nothing here touches
/// mode, rules or policy. Notification text is limited to rule/title, severity and node.
@MainActor @Observable
final class NotificationService {
    static let shared = NotificationService()

    /// False when running as a bare executable (no app bundle): UNUserNotificationCenter would crash.
    let isAvailable: Bool
    private(set) var authorization: String = "not requested"
    private(set) var lastError: String?
    private(set) var enabled: [NotifyCategory: Bool]

    @ObservationIgnored private var watcher = AlertWatcher()
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var delegate: Delegate?
    @ObservationIgnored private var clientProvider: (() -> NetraClient?)?
    @ObservationIgnored private var canMutateProvider: (() -> Bool)?
    @ObservationIgnored private let log = ActivityLog()

    nonisolated private static let ackCategory = "netra.alert"
    nonisolated fileprivate static let ackAction = "netra.ack"

    private static func key(_ c: NotifyCategory) -> String { "netra.notify.\(c.rawValue)" }

    init() {
        let b = Bundle.main
        isAvailable = b.bundleIdentifier != nil && b.bundlePath.hasSuffix(".app")
        var e: [NotifyCategory: Bool] = [:]
        for c in NotifyCategory.allCases {
            e[c] = UserDefaults.standard.object(forKey: Self.key(c)) as? Bool ?? true
        }
        enabled = e
    }

    func isEnabled(_ c: NotifyCategory) -> Bool { enabled[c] ?? true }
    func setEnabled(_ c: NotifyCategory, _ on: Bool) {
        enabled[c] = on
        UserDefaults.standard.set(on, forKey: Self.key(c))
    }

    /// Called after a successful connection; replaces any earlier loop and resets the baseline.
    func start(client: @escaping () -> NetraClient?, canMutate: @escaping () -> Bool, lease: @escaping () -> LeaseStatus?) {
        task?.cancel(); watcher.reset()
        guard isAvailable else { authorization = "unavailable (not running as an app bundle)"; return }
        clientProvider = client; canMutateProvider = canMutate
        task = Task { [weak self] in
            await self?.setup()
            while !Task.isCancelled {
                await self?.tick(lease: lease())
                try? await Task.sleep(nanoseconds: 15 * 1_000_000_000)
            }
        }
    }

    func stop() { task?.cancel(); task = nil }

    private func setup() async {
        let center = UNUserNotificationCenter.current()
        if delegate == nil {
            let d = Delegate { [weak self] id in Task { @MainActor in await self?.acknowledge(alertID: id) } }
            delegate = d
            center.delegate = d
            let ack = UNNotificationAction(identifier: Self.ackAction, title: "Acknowledge", options: [])
            center.setNotificationCategories([UNNotificationCategory(identifier: Self.ackCategory, actions: [ack], intentIdentifiers: [])])
        }
        do {
            let granted = try await center.requestAuthorization(options: [.alert, .sound])
            authorization = granted ? "allowed" : "denied"
        } catch { authorization = "error"; lastError = error.localizedDescription }
    }

    private func tick(lease: LeaseStatus?) async {
        guard let c = clientProvider?() else { return }
        var events: [NotifyEvent] = []
        if isEnabled(.alerts), let s = try? await c.metricsAlerts() { events += watcher.ingest(alerts: s.active) }
        if isEnabled(.incidents), let v = try? await c.json("api/v1/incidents") { events += watcher.ingest(incidents: DetectData.incidents(v)) }
        if isEnabled(.intel), let v = try? await c.json("api/v1/intel/hits") { events += watcher.ingest(intel: DetectData.intelHits(v)) }
        if isEnabled(.lease) { events += watcher.ingest(lease: lease) }
        for e in events { await deliver(e) }
    }

    private func deliver(_ e: NotifyEvent) async {
        let content = UNMutableNotificationContent()
        content.title = e.title; content.body = e.body
        content.threadIdentifier = e.category.rawValue
        if e.severity == "critical" { content.sound = .default }
        if let id = e.alertID {
            content.categoryIdentifier = Self.ackCategory
            content.userInfo = ["alertID": id]
        }
        do { try await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: e.id, content: content, trigger: nil)) }
        catch { lastError = error.localizedDescription }
    }

    /// Guarded ack: preview (a read), then confirm. Needs a token that can mutate; otherwise it does nothing.
    private func acknowledge(alertID: String) async {
        guard let c = clientProvider?(), canMutateProvider?() == true else { return }
        let action = MetricAlertActions.ack(alertID: alertID, label: alertID)
        guard case .success(let spec) = action.build(c, ["id": alertID]) else { return }
        let flow = MutationFlow(spec: spec, client: c, gate: MutationGate(canMutate: true), log: log)
        await flow.runPreview()
        await flow.confirm()
    }

    private final class Delegate: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
        let onAck: @Sendable (String) -> Void
        init(onAck: @escaping @Sendable (String) -> Void) { self.onAck = onAck }
        func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent n: UNNotification) async -> UNNotificationPresentationOptions { [.banner, .list, .sound] }
        func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive r: UNNotificationResponse) async {
            guard r.actionIdentifier == NotificationService.ackAction,
                  let id = r.notification.request.content.userInfo["alertID"] as? String else { return }
            onAck(id)
        }
    }
}
