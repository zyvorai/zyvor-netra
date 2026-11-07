// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Specs for the guarded mutations beyond deny/rollback. Each spec is sent only through
/// `MutationFlow` (preview first, typed phrase and X-Netra-Confirm-Risk for high risk).
public enum ControlMutations {

    // MARK: Mode (PUT /api/v1/ebpf/mode)

    public static let leaseRange: ClosedRange<Int> = 1...(24 * 60)   // minutes; the server accepts 1m–24h

    public static func modeSpec(client c: NetraClient, enforce: Bool, leaseMinutes: Int) -> MutationSpec {
        let minutes = min(max(leaseMinutes, leaseRange.lowerBound), leaseRange.upperBound)
        let target = enforce ? "enforce" : "observe"
        return MutationSpec(
            title: enforce ? "Enforce for \(minutes)m" : "Return to observe",
            risk: enforce ? .high : .low,
            expectedPhrase: "enforce \(minutes)m",
            leaseBound: enforce,
            preview: { c.request("GET", "api/v1/lease") },   // a read: there is no dry-run for mode
            summarize: { v in
                let cur = v["mode"]?.string ?? "unknown"
                return enforce
                    ? "Currently \(cur). Custom rules will be enforced for \(minutes) minute(s), then the datapath fails open to observe."
                    : "Currently \(cur). Enforcement stops immediately; the datapath only observes."
            },
            execute: { _ in
                let body = try? JSONSerialization.data(withJSONObject: ["mode": target])
                let q = enforce ? [URLQueryItem(name: "lease", value: "\(minutes)m")] : []
                return c.request("PUT", "api/v1/ebpf/mode", query: q, body: body)
            })
    }

    // MARK: Feature toggle (POST /api/v1/features/{id}); the server demands Confirm-Risk: high

    public static func featureSpec(client c: NetraClient, id: String, name: String, enable: Bool, restartsWorkload: String?) -> MutationSpec {
        MutationSpec(
            title: "\(enable ? "Enable" : "Disable") \(name)",
            risk: .high,
            expectedPhrase: "\(enable ? "enable" : "disable") \(id)",
            leaseBound: false,
            preview: { c.request("GET", "api/v1/features") },
            summarize: { v in
                let list = v["features"]?.controlItems ?? v.controlItems
                let cur = list.first { $0["id"]?.string == id }?["enabled"]
                let state: String = { if case .bool(let b)? = cur { b ? "enabled" : "disabled" } else { "unknown" } }()
                let note = restartsWorkload.map { " This patches the \($0) environment and triggers a rollout." } ?? ""
                return "\(name) is currently \(state).\(note)"
            },
            execute: { _ in
                let body = try? JSONSerialization.data(withJSONObject: ["enabled": enable])
                return c.request("POST", "api/v1/features/\(id)", body: body)
            })
    }

    // MARK: Capture (PUT/DELETE /api/v1/vms/{node}/capture)

    public struct CaptureParams: Sendable, Equatable {
        public var node = ""
        public var backend = "ebpf"            // "ebpf" | "afpacket"
        public var proto = ""
        public var host = ""
        public var port = 0
        public var durationSeconds = 60
        public var snapLen = 0
        public var maxPPS = 0
        public init() {}

        /// Mirrors the server's rules so the form can explain a rejection before sending.
        public var validationError: String? {
            if node.trimmingCharacters(in: .whitespaces).isEmpty { return "A node is required" }
            if !["ebpf", "afpacket"].contains(backend) { return "Backend must be ebpf or afpacket" }
            if proto.isEmpty && host.trimmingCharacters(in: .whitespaces).isEmpty && port == 0 {
                return "Set a protocol, host or port: unfiltered whole-interface captures are not allowed"
            }
            if !(0...65535).contains(port) { return "Port must be 0–65535" }
            if durationSeconds < 1 || durationSeconds > 300 { return "Duration must be 1–300 seconds" }
            return nil
        }
        var body: Data? {
            var d: [String: Any] = ["backend": backend, "durationSeconds": durationSeconds]
            if !proto.isEmpty { d["protocol"] = proto.lowercased() }
            if !host.isEmpty { d["host"] = host.trimmingCharacters(in: .whitespaces) }
            if port > 0 { d["port"] = port }
            if snapLen > 0 { d["snapLen"] = snapLen }
            if maxPPS > 0 { d["maxPps"] = maxPPS }
            return try? JSONSerialization.data(withJSONObject: d)
        }
    }

    public static func captureStartSpec(client c: NetraClient, params p: CaptureParams) -> MutationSpec {
        let node = p.node.trimmingCharacters(in: .whitespaces)
        return MutationSpec(
            title: "Start capture on \(node)", risk: .medium, expectedPhrase: "", leaseBound: false,
            preview: { c.request("GET", "api/v1/capture/status") },
            summarize: { v in
                let n = v["active"]?.controlItems.count ?? 0
                let on = v["active"]?.controlItems.contains { $0["node"]?.string == node } ?? false
                return "\(n) capture(s) active cluster-wide" + (on ? "; this replaces the one on \(node)" : "")
                    + ". Captures \(p.backend) for \(p.durationSeconds)s with the filter you set (max 25 cluster-wide)."
            },
            execute: { _ in c.request("PUT", "api/v1/vms/\(node)/capture", body: p.body) })
    }

    public static func captureStopSpec(client c: NetraClient, node: String) -> MutationSpec {
        MutationSpec(
            title: "Stop capture on \(node)", risk: .low, expectedPhrase: "", leaseBound: false,
            preview: { c.request("GET", "api/v1/capture/status") },
            summarize: { v in
                let on = v["active"]?.controlItems.contains { $0["node"]?.string == node } ?? false
                return on ? "A capture is active on \(node) and will be stopped." : "No capture is listed as active on \(node)."
            },
            execute: { _ in c.request("DELETE", "api/v1/vms/\(node)/capture") })
    }

    // MARK: Policy: plan (preflight receipt) then apply with X-Netra-Plan-Token

    /// namespace/name from a manifest given as JSON or simple YAML (used only for the confirm phrase;
    /// the server re-derives identity itself).
    public static func policyIdentity(_ manifest: Data) -> (namespace: String, name: String)? {
        if let o = try? JSONSerialization.jsonObject(with: manifest) as? [String: Any],
           let m = o["metadata"] as? [String: Any], let n = m["name"] as? String {
            return ((m["namespace"] as? String) ?? "default", n)
        }
        var inMeta = false, ns = "default", name: String?
        for raw in String(decoding: manifest, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(raw)
            if line.hasPrefix("metadata:") { inMeta = true; continue }
            if inMeta {
                if !line.hasPrefix(" ") && !line.hasPrefix("\t") && !line.isEmpty { break }
                let t = line.trimmingCharacters(in: .whitespaces)
                if t.hasPrefix("name:") { name = String(t.dropFirst(5)).trimmingCharacters(in: CharacterSet(charactersIn: " \"'")) }
                if t.hasPrefix("namespace:") { ns = String(t.dropFirst(10)).trimmingCharacters(in: CharacterSet(charactersIn: " \"'")) }
            }
        }
        return name.map { (ns, $0) }
    }

    public static func policyApplySpec(client c: NetraClient, manifest: Data, namespace: String, name: String,
                                       title: String? = nil, minRisk: Risk = .medium) -> MutationSpec {
        MutationSpec(
            title: title ?? "Apply policy \(namespace)/\(name)", risk: minRisk, expectedPhrase: "apply \(namespace)/\(name)", leaseBound: false,
            preview: { c.request("POST", "api/v1/policies/plan", body: manifest) },
            summarize: { v in
                let plan = v["plan"]
                let risk = plan?["risk"]?.string ?? "unknown"
                let dry = v["dryRun"]
                let passed: Bool = { if case .bool(let b)? = dry?["passed"] { b } else { false } }()
                var s = "Plan risk: \(risk). Kubernetes dry-run \(passed ? "passed" : "FAILED\(dry?["error"]?.string.map { ": " + $0 } ?? "")")."
                if case .array(let w)? = plan?["warnings"], !w.isEmpty { s += " Warnings: " + w.map(\.summary).joined(separator: "; ") }
                if v["receipt"]?["token"]?.string == nil { s += " No plan token was issued, so apply will be refused." }
                return s
            },
            executeWithPreview: { preview, _ in
                var r = c.request("POST", "api/v1/policies/apply", body: manifest)
                if let t = preview["receipt"]?["token"]?.string { r.setValue(t, forHTTPHeaderField: "X-Netra-Plan-Token") }
                return r
            },
            riskFromPreview: { Risk(serverValue: $0["plan"]?["risk"]?.string) },
            execute: { _ in c.request("POST", "api/v1/policies/apply", body: manifest) })
    }

    // MARK: Policy lockdown: build (read-only) -> plan -> apply, and unlock

    /// Body for POST /api/v1/policies/lockdown. The server builds the manifest only (it applies nothing);
    /// an empty selector lets it derive the recommended one from the workload's labels.
    public static func lockdownBuildBody(namespace: String, name: String, kind: String, selector: [String: String]) -> Data? {
        var o: [String: Any] = ["namespace": namespace, "name": name, "kind": kind]
        if !selector.isEmpty { o["selector"] = selector }
        return try? JSONSerialization.data(withJSONObject: o)
    }

    /// Asks the server to build (not apply) a lockdown CiliumNetworkPolicy for a workload.
    public static func buildLockdown(client c: NetraClient, namespace: String, name: String, kind: String,
                                     selector: [String: String] = [:]) async throws -> Data {
        guard let body = lockdownBuildBody(namespace: namespace, name: name, kind: kind, selector: selector) else {
            throw NetraError.transport("could not encode lockdown request")
        }
        return try await c.send(c.request("POST", "api/v1/policies/lockdown", body: body))
    }

    /// Applies a built lockdown manifest through the normal plan-token flow. It cuts all ingress and all
    /// egress but DNS, so it is never below `high`: a typed phrase and the confirm header are always required.
    public static func lockdownApplySpec(client c: NetraClient, manifest: Data, namespace: String, name: String) -> MutationSpec {
        policyApplySpec(client: c, manifest: manifest, namespace: namespace, name: name,
                        title: "Lock down \(namespace)/\(name)", minRisk: .high)
    }

    /// Lifts a lockdown (deletes the workload's `netra-lockdown-*` policy; the server keeps a checkpoint).
    public static func unlockSpec(client c: NetraClient, namespace: String, name: String, kind: String) -> MutationSpec {
        MutationSpec(
            title: "Unlock \(namespace)/\(name)", risk: .medium, expectedPhrase: "unlock \(namespace)/\(name)", leaseBound: false,
            preview: { c.request("GET", "api/v1/workloads/\(kind)/\(namespace)/\(name)") },
            summarize: { v in
                let policy = v["lockdownPolicy"]?.string ?? "the lockdown policy"
                if case .bool(false)? = v["lockedDown"] { return "\(namespace)/\(name) is not locked down; unlocking will return 404." }
                return "Deletes \(policy), restoring the workload's previous network access. A checkpoint is kept for rollback."
            },
            execute: { _ in c.request("DELETE", "api/v1/policies/lockdown/\(namespace)/\(name)") })
    }

    // MARK: Policy rollback to a recorded revision

    /// Rollback uses `?dryRun=true` for its preview and a `confirmRisk=<risk>` query (not a header) to apply.
    public static func policyRollbackSpec(client c: NetraClient, namespace: String, name: String, revision: String) -> MutationSpec {
        let path = "api/v1/policies/\(namespace)/\(name)/rollback/\(revision)"
        return MutationSpec(
            title: "Roll back \(namespace)/\(name) to revision \(revision)", risk: .medium,
            expectedPhrase: "rollback \(namespace)/\(name) \(revision)", leaseBound: false,
            preview: { c.request("POST", path, query: [.init(name: "dryRun", value: "true")]) },
            summarize: { v in
                let risk = v["plan"]?["risk"]?.string ?? "unknown"
                let passed: Bool = { if case .bool(let b)? = v["dryRun"]?["passed"] { b } else { false } }()
                var s = "Plan risk: \(risk). Kubernetes dry-run \(passed ? "passed" : "FAILED\(v["dryRun"]?["error"]?.string.map { ": " + $0 } ?? "")")."
                if case .array(let w)? = v["plan"]?["warnings"], !w.isEmpty { s += " Warnings: " + w.map(\.summary).joined(separator: "; ") }
                return s + " The current state is checkpointed first."
            },
            executeWithPreview: { preview, _ in
                let risk = Risk(serverValue: preview["plan"]?["risk"]?.string)
                let q: [URLQueryItem] = risk.requiresTypedConfirmation ? [.init(name: "confirmRisk", value: risk.confirmHeaderValue)] : []
                return c.request("POST", path, query: q)
            },
            riskFromPreview: { Risk(serverValue: $0["plan"]?["risk"]?.string) },
            execute: { _ in c.request("POST", path) })
    }
}
