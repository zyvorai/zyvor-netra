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
    /// SSO refresh tokens only; API bearer tokens use FileSecretStore via profileStore.
    private let keychain = KeychainStore()
    /// File-backed secrets avoid the login-keychain password dialog that blocks Connect.
    let profileStore = ProfileStore(secrets: FileSecretStore())
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
    /// Kept so a failed whoami can surface pin-mismatch instead of a generic TLS string.
    private var pinningDelegate: PinningDelegate?

    var baseURLText: String
    var connection: Connection = .disconnected
    var lease: LeaseStatus?
    var leaseFetchedAt = Date()
    var healthScore: Double?
    /// Worst raised, un-acked, un-silenced metric alert (menu bar).
    var topAlert: MetricAlert?
    var selection: NavSection? = .overview
    var showConnect = false
    /// Soft status under the badge while bootstrap runs ("Using ~/.netra…").
    var bootstrapNote: String?
    /// When ~/.netra sets NETRA_TLS_INSECURE, first-connect auto-pins the probed leaf (no Trust click).
    private var autoPinInsecureOptIn = false
    private var pollTask: Task<Void, Never>?
    private var didBootstrap = false

    init() {
        let active = profileStore.migrateLegacyIfNeeded()
        profiles = profileStore.load()
        activeProfileID = active.id
        baseURLText = active.urlString
    }

    /// Launch: import ~/.netra, connect. Opens Connect only if there is still no token.
    func start() async {
        await bootstrapFromNetractlIfNeeded(force: true)
        let stored = activeProfile.flatMap { profileStore.token(for: $0) } != nil
        if !stored {
            connection = .disconnected
            showConnect = true
            return
        }
        await connect()
    }

    /// Connect form "Use ~/.netra": re-read home config and connect.
    func reimportNetractlAndConnect() async {
        didBootstrap = false
        await bootstrapFromNetractlIfNeeded(force: true)
        await connect()
    }

    /// Apply an already-parsed netractl config onto the active profile (used after the file picker).
    func applyNetractlConfig(_ cfg: NetractlConfig) async {
        guard !cfg.isEmpty, var p = activeProfile else { return }
        autoPinInsecureOptIn = cfg.requestedInsecureTLS
        if let u = cfg.url { p.urlString = u }
        do {
            let saved = try profileStore.upsert(p)
            if let k = cfg.apiKey { try profileStore.setToken(k, for: saved) }
            reloadProfiles(active: saved.id)
            bootstrapNote = "Signed in from ~/.netra"
        } catch {
            connection = .failed(error.localizedDescription)
        }
    }

    /// Pull URL/token from `~/.netra/env` + `api-key` when the active profile still looks like a first run
    /// (no token, or placeholder localhost URL). `force` refreshes from home even when a token exists.
    func bootstrapFromNetractlIfNeeded(force: Bool = false) async {
        guard force || !didBootstrap else { return }
        didBootstrap = true
        let cfg = await Task.detached(priority: .userInitiated) { NetractlConfig.loadHome() }.value
        guard !cfg.isEmpty, let p = activeProfile else { return }
        let existing = profileStore.token(for: p)
        let placeholder = p.urlString.contains("127.0.0.1") || p.urlString.contains("localhost")
        guard force || existing == nil || placeholder else { return }
        bootstrapNote = "Using ~/.netra…"
        await applyNetractlConfig(cfg)
    }

    var activeProfile: ServerProfile? { profiles.first { $0.id == activeProfileID } ?? profiles.first }

    var client: NetraClient? {
        guard let url = URL(string: baseURLText), url.scheme != nil else { return nil }
        let profile = ConnectionProfile(baseURL: url, token: activeProfile.flatMap { profileStore.token(for: $0) })
        if url.scheme == "https" {
            let pair = NetraClient.pinnedWithDelegate(profile: profile, pinStore: pinStore)
            pinningDelegate = pair.delegate
            return pair.client
        }
        pinningDelegate = nil
        return NetraClient(profile: profile)
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
        // Pass a freshly typed token straight into connect so we never block on a Keychain read
        // of a stale login-keychain item during the same attempt.
        await connect(tokenOverride: token.isEmpty ? nil : token)
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

    /// Keychain prompts and TLS must not run on the MainActor — SecItem* can block the UI thread
    /// waiting for an Allow dialog, which looks like a permanent "Connecting…".
    private enum ConnectOutcome: Sendable {
        case needTrust(CertificateProbeResult)
        case certChanged(host: String, port: Int)
        case connected(WhoAmI, delegate: PinningDelegate?)
        case failed(String)
    }

    func connect(tokenOverride: String? = nil) async {
        pollTask?.cancel()
        epoch += 1; let myEpoch = epoch
        // Only touch Keychain for SSO refresh when we already have a stored bearer; never block Connect on it.
        if tokenOverride == nil { await refreshSSOIfNeeded() }
        guard myEpoch == epoch else { return }
        connection = .connecting
        pendingTrust = nil

        let urlString = baseURLText
        let profile = activeProfile
        let pins = pinStore
        let profiles = profileStore
        let override = tokenOverride

        let outcome: ConnectOutcome = await Task.detached(priority: .userInitiated) {
            guard let url = URL(string: urlString), url.scheme != nil else {
                return .failed("Enter a valid URL")
            }
            let token = override ?? profile.flatMap { profiles.token(for: $0) }
            if url.scheme == "https" {
                do {
                    let probe = try await CertificateProbe.probe(url: url)
                    if let pinned = pins.pin(for: url) {
                        if CertificateFingerprint.normalize(pinned) != CertificateFingerprint.normalize(probe.fingerprint) {
                            return .certChanged(host: probe.host, port: probe.port)
                        }
                    } else if !probe.systemTrusted {
                        return .needTrust(probe)
                    }
                } catch {
                    return .failed(error.localizedDescription)
                }
            }
            let connProfile = ConnectionProfile(baseURL: url, token: token)
            if url.scheme == "https" {
                let pair = NetraClient.pinnedWithDelegate(profile: connProfile, pinStore: pins)
                do {
                    let who = try await pair.client.whoami()
                    return .connected(who, delegate: pair.delegate)
                } catch NetraError.unauthorized {
                    return .failed("Unauthorized — check the API token")
                } catch NetraError.transport(let m) {
                    if let mm = pair.delegate.lastMismatch {
                        return .failed(mm.errorDescription ?? m)
                    }
                    if pins.pin(for: url) != nil {
                        return .failed("TLS failed with a pinned certificate. Use “Forget pinned certificate” if the controller cert was rotated, then Connect again. (\(m))")
                    }
                    return .failed(m)
                } catch NetraError.http(let s, let m) {
                    return .failed("HTTP \(s): \(m)")
                } catch {
                    return .failed(error.localizedDescription)
                }
            } else {
                let c = NetraClient(profile: connProfile)
                do {
                    return .connected(try await c.whoami(), delegate: nil)
                } catch NetraError.unauthorized {
                    return .failed("Unauthorized — check the API token")
                } catch NetraError.transport(let m) {
                    return .failed(m)
                } catch NetraError.http(let s, let m) {
                    return .failed("HTTP \(s): \(m)")
                } catch {
                    return .failed(error.localizedDescription)
                }
            }
        }.value

        guard myEpoch == epoch else { return }
        switch outcome {
        case .needTrust(let probe):
            if autoPinInsecureOptIn {
                // Operator already opted into insecure TLS via netractl; pin once and continue.
                pendingTrust = probe
                bootstrapNote = "Trusting lab certificate…"
                await trustPending()
                bootstrapNote = nil
                return
            }
            pendingTrust = probe
            connection = .failed("Untrusted certificate — review the fingerprint to continue")
        case .certChanged(let host, let port):
            bootstrapNote = nil
            connection = .failed("Certificate changed for \(host):\(port). Remove the pin in Connect settings only if you expected this.")
        case .connected(let who, let delegate):
            pinningDelegate = delegate
            bootstrapNote = nil
            showConnect = false
            connection = .connected(who)
            startPolling()
            NotificationService.shared.start(client: { [weak self] in self?.client }, canMutate: { [weak self] in self?.whoami?.canMutate ?? false }, lease: { [weak self] in self?.lease })
        case .failed(let message):
            bootstrapNote = nil
            connection = .failed(message)
        }
    }

    func trustPending() async {
        guard let p = pendingTrust, let url = URL(string: baseURLText) else { return }
        let pins = pinStore
        let fp = p.fingerprint
        do {
            try await Task.detached(priority: .userInitiated) {
                try pins.setPin(fp, for: url)
            }.value
        } catch {
            connection = .failed("Couldn't store pin: \(error.localizedDescription)")
            return
        }
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
