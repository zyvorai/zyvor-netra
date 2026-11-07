// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Minimal secret storage so the profile store is testable without the real Keychain.
public protocol SecretStore: Sendable {
    func set(_ secret: String, account: String) throws
    func get(account: String) -> String?
    func delete(account: String)
}
extension KeychainStore: SecretStore {}

/// Per-profile OIDC settings. Public client: there is no client secret anywhere.
public struct OIDCSettings: Codable, Equatable, Sendable {
    public var issuer: String
    public var clientID: String
    public var scopes: String
    /// Send the access token instead of the ID token. The server checks `aud` against NETRA_OIDC_AUDIENCE,
    /// so pick whichever token carries that audience for your IdP.
    public var useAccessToken: Bool
    public init(issuer: String, clientID: String, scopes: String = "openid profile email offline_access", useAccessToken: Bool = false) {
        self.issuer = issuer; self.clientID = clientID; self.scopes = scopes; self.useAccessToken = useAccessToken
    }
}

/// A saved connection. Contains no secrets; the token lives in the Keychain under `tokenAccount`.
public struct ServerProfile: Codable, Equatable, Identifiable, Sendable {
    public var id: String
    public var name: String
    public var urlString: String
    public var oidc: OIDCSettings?
    public init(id: String = UUID().uuidString, name: String, urlString: String, oidc: OIDCSettings? = nil) {
        self.id = id; self.name = name; self.urlString = urlString; self.oidc = oidc
    }
    public var tokenAccount: String { "profile:\(id)" }
    public var refreshAccount: String { "profile:\(id):refresh" }
    public var url: URL? { URL(string: urlString) }
}

public enum ProfileError: Error, Equatable, LocalizedError, Sendable {
    case emptyName, invalidURL, duplicateName, duplicateURL, invalidOIDC(String), notFound
    public var errorDescription: String? {
        switch self {
        case .emptyName: "Give the profile a name."
        case .invalidURL: "Enter a valid http(s) controller URL."
        case .duplicateName: "Another profile already has that name."
        case .duplicateURL: "Another profile already points at that URL."
        case .invalidOIDC(let m): m
        case .notFound: "Profile not found."
        }
    }
}

/// Named connection profiles persisted as JSON (no secrets) in UserDefaults.
public struct ProfileStore: @unchecked Sendable {
    public static let profilesKey = "netra.profiles.v1"
    public static let activeKey = "netra.profiles.active"
    public static let legacyURLKey = "netra.baseURL"

    let defaults: UserDefaults
    let secrets: SecretStore

    public init(defaults: UserDefaults = .standard, secrets: SecretStore = KeychainStore()) {
        self.defaults = defaults; self.secrets = secrets
    }

    // MARK: normalisation / validation

    /// Trim, require http(s) with a host, drop trailing slashes.
    public static func normalizeURL(_ s: String) -> String? {
        var t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        while t.hasSuffix("/") { t.removeLast() }
        guard let u = URL(string: t), let scheme = u.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let h = u.host, !h.isEmpty else { return nil }
        return t
    }
    /// Identity of a server for uniqueness: scheme://host:port, lowercased.
    static func urlIdentity(_ s: String) -> String? {
        guard let n = normalizeURL(s), let u = URL(string: n), let h = u.host?.lowercased() else { return nil }
        let scheme = u.scheme!.lowercased()
        return "\(scheme)://\(h):\(u.port ?? (scheme == "http" ? 80 : 443))\(u.path)"
    }

    public func validate(_ p: ServerProfile) throws -> ServerProfile {
        var p = p
        p.name = p.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !p.name.isEmpty else { throw ProfileError.emptyName }
        guard let n = Self.normalizeURL(p.urlString), let ident = Self.urlIdentity(p.urlString) else { throw ProfileError.invalidURL }
        p.urlString = n
        if var o = p.oidc {
            o.issuer = o.issuer.trimmingCharacters(in: .whitespacesAndNewlines)
            o.clientID = o.clientID.trimmingCharacters(in: .whitespacesAndNewlines)
            if o.issuer.isEmpty && o.clientID.isEmpty { p.oidc = nil }
            else {
                guard let u = URL(string: o.issuer), u.scheme == "https", u.host != nil else {
                    throw ProfileError.invalidOIDC("The issuer must be an https URL.")
                }
                guard !o.clientID.isEmpty else { throw ProfileError.invalidOIDC("Enter the OIDC client ID.") }
                p.oidc = o
            }
        }
        for other in load() where other.id != p.id {
            if other.name.caseInsensitiveCompare(p.name) == .orderedSame { throw ProfileError.duplicateName }
            if Self.urlIdentity(other.urlString) == ident { throw ProfileError.duplicateURL }
        }
        return p
    }

    // MARK: persistence

    public func load() -> [ServerProfile] {
        guard let d = defaults.data(forKey: Self.profilesKey),
              let ps = try? JSONDecoder().decode([ServerProfile].self, from: d) else { return [] }
        return ps
    }
    private func save(_ ps: [ServerProfile]) {
        if let d = try? JSONEncoder().encode(ps) { defaults.set(d, forKey: Self.profilesKey) }
    }
    public var activeID: String? {
        get { defaults.string(forKey: Self.activeKey) }
        nonmutating set { if let v = newValue { defaults.set(v, forKey: Self.activeKey) } else { defaults.removeObject(forKey: Self.activeKey) } }
    }
    public func active() -> ServerProfile? {
        let ps = load()
        return ps.first { $0.id == activeID } ?? ps.first
    }

    /// Adds or replaces (by id) after validation. Returns the stored profile.
    @discardableResult
    public func upsert(_ p: ServerProfile) throws -> ServerProfile {
        let v = try validate(p)
        var ps = load()
        if let i = ps.firstIndex(where: { $0.id == v.id }) {
            // Changing the server of an existing profile must not carry its token to the new server.
            if Self.urlIdentity(ps[i].urlString) != Self.urlIdentity(v.urlString) { clearSecrets(v) }
            ps[i] = v
        } else { ps.append(v) }
        save(ps)
        return v
    }

    /// Removes the profile and its Keychain secrets. Returns the URL whose pin may now be orphaned.
    @discardableResult
    public func remove(id: String) -> ServerProfile? {
        var ps = load()
        guard let i = ps.firstIndex(where: { $0.id == id }) else { return nil }
        let gone = ps.remove(at: i)
        clearSecrets(gone)
        save(ps)
        if activeID == id { activeID = ps.first?.id }
        return gone
    }

    public func clearSecrets(_ p: ServerProfile) {
        secrets.delete(account: p.tokenAccount); secrets.delete(account: p.refreshAccount)
    }
    public func token(for p: ServerProfile) -> String? {
        let t = secrets.get(account: p.tokenAccount); return (t?.isEmpty ?? true) ? nil : t
    }
    public func setToken(_ t: String?, for p: ServerProfile) throws {
        if let t, !t.isEmpty { try secrets.set(t, account: p.tokenAccount) } else { secrets.delete(account: p.tokenAccount) }
    }

    // MARK: migration

    /// First launch after upgrade: turn the single `netra.baseURL` + Keychain account (the URL text)
    /// into a "Default" profile, moving the token to the per-profile account. Idempotent.
    @discardableResult
    public func migrateLegacyIfNeeded(defaultURL: String = "http://127.0.0.1:8080") -> ServerProfile {
        if let a = active() { return a }
        let legacy = defaults.string(forKey: Self.legacyURLKey)
        let raw = legacy ?? defaultURL
        let url = Self.normalizeURL(raw) ?? defaultURL
        let p = ServerProfile(name: "Default", urlString: url)
        save([p]); activeID = p.id
        // The legacy token was keyed by the exact URL text the user typed.
        for acct in [raw, url] {
            if let t = secrets.get(account: acct), !t.isEmpty {
                try? secrets.set(t, account: p.tokenAccount)
                secrets.delete(account: acct)
                break
            }
        }
        return p
    }
}
