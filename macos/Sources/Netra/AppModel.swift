// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import AppKit
import AuthenticationServices
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
    let profileStore = ProfileStore()
    /// Saved connection profiles (no secrets) and the one in use.
    var profiles: [ServerProfile] = []
    var activeProfileID: String?
    /// Bumped on every connect/switch so a slow, superseded connect cannot overwrite newer state.
    private var epoch = 0
    private var oidcExpiry: Date?
    private var webAuth: ASWebAuthenticationSession?
    private let webAuthContext = WebAuthContext()
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
        let active = profileStore.migrateLegacyIfNeeded()
        profiles = profileStore.load()
        activeProfileID = active.id
        baseURLText = active.urlString
    }

    var activeProfile: ServerProfile? { profiles.first { $0.id == activeProfileID } ?? profiles.first }

    var client: NetraClient? {
        guard let url = URL(string: baseURLText), url.scheme != nil else { return nil }
        let profile = ConnectionProfile(baseURL: url, token: activeProfile.flatMap { profileStore.token(for: $0) })
        return url.scheme == "https" ? NetraClient.pinned(profile: profile, pinStore: pinStore) : NetraClient(profile: profile)
    }
    var whoami: WhoAmI? { if case .connected(let w) = connection { w } else { nil } }
    var gate: MutationGate { MutationGate(canMutate: whoami?.canMutate ?? false) }
    var effectiveMode: String {
        guard let l = lease else { return "unknown" }
        return LeaseTracker(expiresAt: l.leaseExpiresAt).effectiveMode(declared: l.mode)
    }

    /// Saves the edited URL/token onto the ACTIVE profile and reconnects.
    func saveAndConnect(url: String, token: String, name: String? = nil, oidc: OIDCSettings? = nil) async {
        guard var p = activeProfile else { return }
        p.urlString = url
        if let name { p.name = name }
        if let oidc { p.oidc = oidc }
        do {
            let saved = try profileStore.upsert(p)   // drops the old token if the server changed
            if !token.isEmpty { try profileStore.setToken(token, for: saved) }   // blank keeps the stored token
            reloadProfiles(active: saved.id)
        } catch { connection = .failed(error.localizedDescription); return }
        await connect()
    }

    /// Forget the stored token (and SSO refresh token) of the active profile.
    func clearToken() {
        guard let p = activeProfile else { return }
        profileStore.clearSecrets(p)
        oidcExpiry = nil
    }

    private func reloadProfiles(active: String?) {
        profiles = profileStore.load()
        activeProfileID = active ?? profiles.first?.id
        profileStore.activeID = activeProfileID
        baseURLText = activeProfile?.urlString ?? baseURLText
    }

    /// Adds (or edits, when `profile.id` exists) a profile. Does not switch to it.
    @discardableResult
    func saveProfile(_ profile: ServerProfile, token: String?) throws -> ServerProfile {
        let saved = try profileStore.upsert(profile)
        if let token, !token.isEmpty { try profileStore.setToken(token, for: saved) }
        let wasActive = activeProfileID
        reloadProfiles(active: wasActive ?? saved.id)
        return saved
    }

    /// Full disconnect, then connect to another profile. Nothing (token, pin prompt, lease, alerts) carries over.
    func switchProfile(_ id: String) async {
        guard profiles.contains(where: { $0.id == id }), id != activeProfileID || connection != .connecting else { return }
        disconnect()
        pendingTrust = nil
        oidcExpiry = nil
        reloadProfiles(active: id)
        await connect()
    }

    func deleteProfile(_ id: String) async {
        let wasActive = id == activeProfileID
        if wasActive { disconnect() }
        guard let gone = profileStore.remove(id: id) else { return }
        // Drop the pin only if no remaining profile shares that host:port.
        if let u = gone.url, let h = u.host {
            let port = u.port ?? (u.scheme == "http" ? 80 : 443)
            let shared = profileStore.load().contains { $0.url?.host?.lowercased() == h.lowercased() && ($0.url?.port ?? (($0.url?.scheme == "http") ? 80 : 443)) == port }
            if !shared { pinStore.removePin(host: h, port: port) }
        }
        if profileStore.load().isEmpty { profileStore.migrateLegacyIfNeeded() }
        reloadProfiles(active: wasActive ? nil : activeProfileID)
        if wasActive { await connect() }
    }

    // MARK: SSO (authorization code + PKCE; the controller verifies the JWT itself)

    func signInWithSSO() async {
        guard let p = activeProfile, let o = p.oidc else { connection = .failed("Set the OIDC issuer and client ID for this profile first."); return }
        disconnect()
        connection = .connecting
        let flow = OIDCFlow(settings: o)
        do {
            let ep = try await flow.discover()
            let req = flow.makeAuthRequest(endpoints: ep)
            let callback = try await runWebAuth(url: req.url)
            let code = try flow.code(from: callback, request: req)
            let tokens = try await flow.exchange(code: code, request: req, endpoints: ep)
            try storeOIDC(tokens, for: p)
            await connect()
        } catch let e as ASWebAuthenticationSessionError where e.code == .canceledLogin {
            connection = .disconnected
        } catch {
            connection = .failed(error.localizedDescription)
        }
    }

    private func storeOIDC(_ t: OIDCTokens, for p: ServerProfile) throws {
        try profileStore.setToken(t.bearer, for: p)
        if let r = t.refreshToken { try keychain.set(r, account: p.refreshAccount) }
        oidcExpiry = t.expiresAt
    }

    private func runWebAuth(url: URL) async throws -> URL {
        try await withCheckedThrowingContinuation { cont in
            let s = ASWebAuthenticationSession(url: url, callbackURLScheme: OIDCFlow.callbackScheme) { u, err in
                if let u { cont.resume(returning: u) } else { cont.resume(throwing: err ?? OIDCError.missingCode) }
            }
            s.presentationContextProvider = webAuthContext
            webAuth = s
            if !s.start() { cont.resume(throwing: OIDCError.providerError("Could not open the sign-in window.")) }
        }
    }

    /// Refreshes an expiring SSO token (client-side against the IdP; the server has no refresh endpoint).
    private func refreshSSOIfNeeded() async {
        guard let p = activeProfile, let o = p.oidc, let cur = profileStore.token(for: p) else { return }
        let exp = oidcExpiry ?? (OIDCFlow.claim(cur, "exp") as? Double).map { Date(timeIntervalSince1970: $0) }
        guard let exp, OIDCFlow.needsRefresh(OIDCTokens(bearer: cur, refreshToken: nil, expiresAt: exp)),
              let rt = keychain.get(account: p.refreshAccount) else { return }
        let flow = OIDCFlow(settings: o)
        if let ep = try? await flow.discover(), let t = try? await flow.refresh(refreshToken: rt, endpoints: ep),
           activeProfileID == p.id { try? storeOIDC(t, for: p) }
    }

    func connect() async {
        pollTask?.cancel()
        epoch += 1; let myEpoch = epoch
        await refreshSSOIfNeeded()
        guard myEpoch == epoch else { return }
        guard let c = client else { connection = .failed("Enter a valid URL"); return }
        connection = .connecting
        if let url = URL(string: baseURLText), url.scheme == "https" {
            do {
                let probe = try await CertificateProbe.probe(url: url)
                guard myEpoch == epoch else { return }
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
            let who = try await c.whoami()
            guard myEpoch == epoch else { return }
            connection = .connected(who)
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
        epoch += 1
        pollTask?.cancel(); pollTask = nil
        NotificationService.shared.stop()
        connection = .disconnected; lease = nil; healthScore = nil; topAlert = nil
    }

    private func startPolling() {
        pollTask = Task { [weak self] in
            var delay: UInt64 = 5
            while !Task.isCancelled {
                guard let self else { return }
                await self.refreshSSOIfNeeded()
                guard let c = self.client else { return }
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
                    self.connection = .failed(self.activeProfile?.oidc != nil ? "Session expired — sign in again" : "Session expired — reconnect"); return
                } catch {
                    delay = min(delay * 2, 60)   // back off while the controller is unreachable
                }
                try? await Task.sleep(nanoseconds: delay * 1_000_000_000)
            }
        }
    }
}

/// Anchors the SSO sheet to the key window.
final class WebAuthContext: NSObject, ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        NSApp.keyWindow ?? NSApp.windows.first ?? ASPresentationAnchor()
    }
}
