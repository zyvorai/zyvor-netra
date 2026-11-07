// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

public enum Risk: String, Sendable {
    case low, medium, high, critical
    /// High and critical changes need a typed phrase and the X-Netra-Confirm-Risk header.
    public var requiresTypedConfirmation: Bool { self == .high || self == .critical }
    /// The server compares the header to the plan's own risk, so critical must say "critical".
    public var confirmHeaderValue: String { self == .critical ? "critical" : "high" }
    public init(serverValue: String?) { self = Risk(rawValue: (serverValue ?? "").lowercased()) ?? .high }
}

public enum GateDecision: Sendable, Equatable {
    case allowed(confirmRiskHeader: Bool)
    case needsPreview
    case needsTypedConfirmation(phrase: String)
    case blocked(reason: String)
}

/// Client-side mirror of Netra's safety model. The server remains authoritative;
/// this only keeps the UI honest: read-only roles can't mutate, every mutation is
/// previewed first, and high-risk actions need a typed phrase and send X-Netra-Confirm-Risk.
public struct MutationGate: Sendable {
    public var canMutate: Bool
    public init(canMutate: Bool) { self.canMutate = canMutate }

    public func decide(risk: Risk, previewed: Bool, typedPhrase: String?, expectedPhrase: String) -> GateDecision {
        guard canMutate else { return .blocked(reason: "This token is read-only") }
        guard previewed else { return .needsPreview }
        if risk.requiresTypedConfirmation {
            guard typedPhrase == expectedPhrase else { return .needsTypedConfirmation(phrase: expectedPhrase) }
            return .allowed(confirmRiskHeader: true)
        }
        return .allowed(confirmRiskHeader: false)
    }
}

/// Enforce is lease-bounded and fails open to observe.
public struct LeaseTracker: Sendable, Equatable {
    public var expiresAt: Date?
    public init(expiresAt: Date?) { self.expiresAt = expiresAt }
    public func remaining(now: Date = Date()) -> TimeInterval { max(0, (expiresAt ?? now).timeIntervalSince(now)) }
    public func effectiveMode(declared: String, now: Date = Date()) -> String {
        declared == "enforce" && remaining(now: now) <= 0 ? "observe" : declared
    }
}
