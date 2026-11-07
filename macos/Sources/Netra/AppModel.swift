// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

enum Connection: Equatable {
    case disconnected
    case connecting
    case connected(WhoAmI)
    case failed(String)
}

@MainActor @Observable
final class AppModel {
    private let keychain = KeychainStore()
    private let urlKey = "netra.baseURL"
    let pinStore = PinStore()
    /// Set when an https server presents an untrusted, unpinned certificate; RootView shows TrustPrompt.
    var pendingTrust: CertificateProbeResult?

    var baseURLText: String
    var connection: Connection = .disconnected
    var lease: LeaseStatus?
    var leaseFetchedAt = Date()
    var healthScore: Double?
    /// Worst raised, un-acked, un-silenced metric alert (menu bar).
    var topAlert: MetricAlert?
    var selection: NavSection? = .overview
    var showConnect = false
    private var pollTask: Task<Void, Never>?

    init() {
        baseURLText = UserDefaults.standard.string(forKey: "netra.baseURL") ?? "http://127.0.0.1:8080"
    }

    var client: NetraClient? {
        guard let url = URL(string: baseURLText), url.scheme != nil else { return nil }
        let profile = ConnectionProfile(baseURL: url, token: keychain.get(account: baseURLText))
        return url.scheme == "https" ? NetraClient.pinned(profile: profile, pinStore: pinStore) : NetraClient(profile: profile)
    }
    var whoami: WhoAmI? { if case .connected(let w) = connection { w } else { nil } }
    var gate: MutationGate { MutationGate(canMutate: whoami?.canMutate ?? false) }
    var effectiveMode: String {
        guard let l = lease else { return "unknown" }
        return LeaseTracker(expiresAt: l.leaseExpiresAt).effectiveMode(declared: l.mode)
    }

    func saveAndConnect(url: String, token: String) async {
        baseURLText = url.trimmingCharacters(in: .whitespaces)
        UserDefaults.standard.set(baseURLText, forKey: urlKey)
        if token.isEmpty { keychain.delete(account: baseURLText) }
        else { try? keychain.set(token, account: baseURLText) }
        await connect()
    }

    func connect() async {
        pollTask?.cancel()
        guard let c = client else { connection = .failed("Enter a valid URL"); return }
        connection = .connecting
        if let url = URL(string: baseURLText), url.scheme == "https" {
            do {
                let probe = try await CertificateProbe.probe(url: url)
                if let pinned = pinStore.pin(for: url) {
                    // A pinned server must keep presenting the pinned certificate; never re-pin automatically.
                    if CertificateFingerprint.normalize(pinned) != CertificateFingerprint.normalize(probe.fingerprint) {
                        connection = .failed("Certificate changed for \(probe.host):\(probe.port). Remove the pin in Connect settings only if you expected this.")
                        return
                    }
                } else if !probe.systemTrusted {
                    pendingTrust = probe
                    connection = .failed("Untrusted certificate — review the fingerprint to continue")
                    return
                }
            } catch {
                connection = .failed(error.localizedDescription)
                return
            }
        }
        do {
            connection = .connected(try await c.whoami())
            startPolling()
            NotificationService.shared.start(client: { [weak self] in self?.client }, canMutate: { [weak self] in self?.whoami?.canMutate ?? false }, lease: { [weak self] in self?.lease })
        } catch NetraError.unauthorized {
            connection = .failed("Unauthorized — check the API token")
        } catch NetraError.transport(let m) {
            connection = .failed(m)
        } catch NetraError.http(let s, let m) {
            connection = .failed("HTTP \(s): \(m)")
        } catch {
            connection = .failed(error.localizedDescription)
        }
    }

    func trustPending() async {
        guard let p = pendingTrust, let url = URL(string: baseURLText) else { return }
        do { try pinStore.setPin(p.fingerprint, for: url) } catch { connection = .failed("Couldn't store pin: \(error.localizedDescription)"); return }
        pendingTrust = nil
        await connect()
    }

    func forgetPin() {
        if let u = URL(string: baseURLText), let h = u.host { pinStore.removePin(host: h, port: u.port ?? 443) }
    }

    func disconnect() {
        pollTask?.cancel()
        NotificationService.shared.stop()
        connection = .disconnected; lease = nil; healthScore = nil; topAlert = nil
    }

    private func startPolling() {
        pollTask = Task { [weak self] in
            var delay: UInt64 = 5
            while !Task.isCancelled {
                guard let self, let c = self.client else { return }
                do {
                    let l = try await c.lease()
                    let h = try? await c.json("api/v1/ebpf/health")
                    self.lease = l; self.leaseFetchedAt = Date()
                    self.healthScore = h?["summary"]?["healthScore"]?.double
                    if let a = try? await c.metricsAlerts() {
                        self.topAlert = a.active.filter { $0.acked != true && $0.silenced != true && DetectData.severityRank($0.status) >= 2 }
                            .max { DetectData.severityRank($0.status) < DetectData.severityRank($1.status) }
                    }
                    delay = 5
                } catch NetraError.unauthorized {
                    self.connection = .failed("Session expired — reconnect"); return
                } catch {
                    delay = min(delay * 2, 60)   // back off while the controller is unreachable
                }
                try? await Task.sleep(nanoseconds: delay * 1_000_000_000)
            }
        }
    }
}
