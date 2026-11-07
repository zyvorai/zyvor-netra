// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation
import Observation

public struct ActivityEntry: Identifiable, Sendable, Equatable {
    public enum Outcome: String, Sendable { case blocked, attempted, succeeded, failed }
    public let id = UUID()
    public let at: Date
    public let title: String
    public let method: String
    public let path: String
    public let outcome: Outcome
    public let detail: String
}

/// In-memory log of every attempted mutation (never persisted, never contains tokens).
@MainActor @Observable
public final class ActivityLog {
    public private(set) var entries: [ActivityEntry] = []
    public init() {}
    public func append(title: String, method: String, path: String, outcome: ActivityEntry.Outcome, detail: String = "") {
        entries.insert(.init(at: Date(), title: title, method: method, path: path, outcome: outcome, detail: detail), at: 0)
        if entries.count > 500 { entries.removeLast(entries.count - 500) }
    }
}

/// Describes one guarded mutation. `preview` is a non-mutating dry run (or a read) that must
/// succeed before `execute` is allowed. `execute` receives whether to send X-Netra-Confirm-Risk.
public struct MutationSpec: Sendable {
    public var title: String
    public var risk: Risk
    public var expectedPhrase: String
    /// True when the change only takes effect under an enforce lease (fails open to observe).
    public var leaseBound: Bool
    public var preview: @Sendable () -> URLRequest
    public var summarize: @Sendable (JSONValue) -> String
    public var execute: @Sendable (_ confirmRisk: Bool) -> URLRequest
    /// When set, replaces `execute`: the request depends on the preview result (e.g. a plan token).
    public var executeWithPreview: (@Sendable (_ preview: JSONValue, _ confirmRisk: Bool) -> URLRequest)?
    /// When set, the risk the server reported in the preview overrides `risk` (never below it).
    public var riskFromPreview: (@Sendable (JSONValue) -> Risk)?
    public init(title: String, risk: Risk, expectedPhrase: String, leaseBound: Bool,
                preview: @escaping @Sendable () -> URLRequest,
                summarize: @escaping @Sendable (JSONValue) -> String = { $0.summary },
                executeWithPreview: (@Sendable (JSONValue, Bool) -> URLRequest)? = nil,
                riskFromPreview: (@Sendable (JSONValue) -> Risk)? = nil,
                execute: @escaping @Sendable (Bool) -> URLRequest) {
        self.executeWithPreview = executeWithPreview; self.riskFromPreview = riskFromPreview
        self.title = title; self.risk = risk; self.expectedPhrase = expectedPhrase; self.leaseBound = leaseBound
        self.preview = preview; self.summarize = summarize; self.execute = execute
    }
}

/// Drives preview -> typed confirmation -> send, enforcing MutationGate and logging everything.
@MainActor @Observable
public final class MutationFlow {
    public enum Phase: Equatable { case idle, previewing, running, done(String), failed(String) }

    public let spec: MutationSpec
    public var typedPhrase = ""
    public private(set) var previewSummary: String?
    public private(set) var previewValue: JSONValue?
    public private(set) var phase: Phase = .idle
    private let client: NetraClient
    private let gate: MutationGate
    private let log: ActivityLog

    public init(spec: MutationSpec, client: NetraClient, gate: MutationGate, log: ActivityLog) {
        self.spec = spec; self.client = client; self.gate = gate; self.log = log
    }

    public var previewed: Bool { previewSummary != nil }
    /// The stricter of the declared risk and whatever the server reported in the preview.
    public var effectiveRisk: Risk {
        guard let v = previewValue, let f = spec.riskFromPreview else { return spec.risk }
        let r = f(v)
        return Self.rank(r) >= Self.rank(spec.risk) ? r : spec.risk
    }
    private static func rank(_ r: Risk) -> Int { [Risk.low: 0, .medium: 1, .high: 2, .critical: 3][r]! }
    private func request(confirmRisk: Bool) -> URLRequest {
        var r = (spec.executeWithPreview.flatMap { f in previewValue.map { f($0, confirmRisk) } }) ?? spec.execute(confirmRisk)
        if confirmRisk { r.setValue(effectiveRisk.confirmHeaderValue, forHTTPHeaderField: "X-Netra-Confirm-Risk") }
        return r
    }
    public var decision: GateDecision {
        gate.decide(risk: effectiveRisk, previewed: previewed,
                    typedPhrase: effectiveRisk.requiresTypedConfirmation ? typedPhrase : nil, expectedPhrase: spec.expectedPhrase)
    }
    public var canPreview: Bool { gate.canMutate && phase != .previewing && phase != .running }
    public var canConfirm: Bool {
        if case .allowed = decision, phase != .running, phase != .previewing, !isDone { return true }
        return false
    }
    private var isDone: Bool { if case .done = phase { true } else { false } }

    public func runPreview() async {
        let req = spec.preview()
        guard gate.canMutate else {
            log.append(title: spec.title + " (preview)", method: req.httpMethod ?? "", path: req.url?.path ?? "", outcome: .blocked, detail: "read-only token")
            return
        }
        phase = .previewing
        do {
            let data = try await client.send(req)
            let v = (try? JSONDecoder().decode(JSONValue.self, from: data)) ?? .null
            previewValue = v
            previewSummary = spec.summarize(v)
            phase = .idle
        } catch {
            previewSummary = nil; previewValue = nil
            phase = .failed("Preview failed: \(Self.describe(error))")
        }
    }

    public func confirm() async {
        let probe = request(confirmRisk: false)
        let method = probe.httpMethod ?? "", path = probe.url?.path ?? ""
        switch decision {
        case .blocked(let r):
            log.append(title: spec.title, method: method, path: path, outcome: .blocked, detail: r); return
        case .needsPreview:
            log.append(title: spec.title, method: method, path: path, outcome: .blocked, detail: "no preview"); return
        case .needsTypedConfirmation:
            log.append(title: spec.title, method: method, path: path, outcome: .blocked, detail: "confirmation phrase not typed"); return
        case .allowed(let header):
            phase = .running
            log.append(title: spec.title, method: method, path: path, outcome: .attempted, detail: header ? "confirm-risk: high" : "")
            do {
                let data = try await client.send(request(confirmRisk: header))
                let msg = "HTTP OK, \(data.count) bytes"
                log.append(title: spec.title, method: method, path: path, outcome: .succeeded, detail: msg)
                phase = .done(msg)
            } catch {
                let m = Self.describe(error)
                log.append(title: spec.title, method: method, path: path, outcome: .failed, detail: m)
                phase = .failed(m)
            }
        }
    }

    static func describe(_ e: Error) -> String {
        switch e as? NetraError {
        case .http(let s, let m): "HTTP \(s): \(m)"
        case .unauthorized: "unauthorized"
        case .transport(let m): m
        case nil: e.localizedDescription
        }
    }
}
